import { SsoProviderService } from './sso-provider.service';
import { AuthProviderRepo } from '../repos/auth-provider.repo';
import { EncryptionService } from '../../integrations/encryption/encryption.service';
import { WorkspaceRepo } from '@docmost/db/repos/workspace/workspace.repo';

describe('SsoProviderService', () => {
  let service: SsoProviderService;
  let authProviderRepo: jest.Mocked<AuthProviderRepo>;
  let encryptionService: jest.Mocked<EncryptionService>;
  let workspaceRepo: jest.Mocked<WorkspaceRepo>;

  beforeEach(() => {
    authProviderRepo = {
      findByWorkspaceId: jest.fn(),
      findById: jest.fn(),
      findFirstByType: jest.fn(),
      insertProvider: jest.fn(),
      updateProvider: jest.fn(),
      softDeleteProvider: jest.fn(),
    } as any;

    encryptionService = {
      encrypt: jest.fn((val: string) => `enc:${val}`),
      decrypt: jest.fn((val: string) => val.replace('enc:', '')),
    } as any;

    workspaceRepo = {
      findFirst: jest.fn(),
      updateWorkspace: jest.fn(),
    } as any;

    service = new SsoProviderService(
      authProviderRepo,
      encryptionService,
      workspaceRepo,
    );
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('getProviders', () => {
    it('should return providers with decrypted secrets', async () => {
      authProviderRepo.findByWorkspaceId.mockResolvedValue([
        {
          id: 'p1',
          name: 'Google',
          type: 'oidc',
          oidcClientSecret: 'enc:secret123',
          workspaceId: 'w1',
        } as any,
      ]);

      const providers = await service.getProviders('w1');
      expect(providers).toHaveLength(1);
      expect(providers[0].oidcClientSecret).toBe('secret123');
    });

    it('should trigger on-demand sync from env if no providers exist and OIDC_ISSUER is set', async () => {
      process.env.OIDC_ISSUER = 'https://issuer.example.com';
      process.env.OIDC_CLIENT_ID = 'cid';
      process.env.OIDC_CLIENT_SECRET = 'csecret';

      workspaceRepo.findFirst.mockResolvedValue({ id: 'w1' } as any);
      authProviderRepo.findByWorkspaceId
        .mockResolvedValueOnce([])
        .mockResolvedValueOnce([
          {
            id: 'p-new',
            name: 'OIDC',
            type: 'oidc',
            oidcClientSecret: 'enc:csecret',
            workspaceId: 'w1',
          } as any,
        ]);
      authProviderRepo.findFirstByType.mockResolvedValue(undefined);

      const providers = await service.getProviders('w1');

      expect(authProviderRepo.insertProvider).toHaveBeenCalled();
      expect(providers).toHaveLength(1);

      delete process.env.OIDC_ISSUER;
      delete process.env.OIDC_CLIENT_ID;
      delete process.env.OIDC_CLIENT_SECRET;
    });
  });

  describe('createProvider', () => {
    it('should insert new provider with default disabled status', async () => {
      authProviderRepo.insertProvider.mockResolvedValue({
        id: 'p2',
        name: 'OIDC',
        type: 'oidc',
        isEnabled: false,
        allowSignup: false,
        workspaceId: 'w1',
      } as any);

      const result = await service.createProvider(
        { name: 'OIDC', type: 'oidc' },
        'w1',
        'u1',
      );

      expect(authProviderRepo.insertProvider).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'OIDC',
          type: 'oidc',
          isEnabled: false,
          allowSignup: false,
          workspaceId: 'w1',
          creatorId: 'u1',
        }),
      );
      expect(result.id).toBe('p2');
    });
  });

  describe('updateProvider', () => {
    it('should encrypt oidcClientSecret when updating', async () => {
      authProviderRepo.findById.mockResolvedValue({
        id: 'p1',
        workspaceId: 'w1',
      } as any);

      authProviderRepo.updateProvider.mockResolvedValue({
        id: 'p1',
        name: 'Updated OIDC',
        oidcClientSecret: 'enc:newSecret',
        workspaceId: 'w1',
      } as any);

      const result = await service.updateProvider(
        {
          providerId: 'p1',
          name: 'Updated OIDC',
          oidcClientSecret: 'newSecret',
          isEnabled: true,
        },
        'w1',
      );

      expect(encryptionService.encrypt).toHaveBeenCalledWith('newSecret');
      expect(authProviderRepo.updateProvider).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'Updated OIDC',
          oidcClientSecret: 'enc:newSecret',
          isEnabled: true,
        }),
        'p1',
        'w1',
      );
      expect(result.oidcClientSecret).toBe('newSecret');
    });
  });

  describe('deleteProvider', () => {
    it('should soft delete provider', async () => {
      authProviderRepo.findById.mockResolvedValue({
        id: 'p1',
        workspaceId: 'w1',
      } as any);
      authProviderRepo.softDeleteProvider.mockResolvedValue(true);

      await service.deleteProvider('p1', 'w1');
      expect(authProviderRepo.softDeleteProvider).toHaveBeenCalledWith(
        'p1',
        'w1',
      );
    });
  });

  describe('syncFromEnvironmentVariables (OIDC_ENFORCE)', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      process.env = { ...originalEnv };
      delete process.env.OIDC_ENFORCE;
      delete process.env.OIDC_ISSUER;
      delete process.env.OIDC_CLIENT_ID;
      delete process.env.OIDC_CLIENT_SECRET;
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it('should enforce SSO on workspace when OIDC_ENFORCE is true', async () => {
      process.env.OIDC_ENFORCE = 'true';
      workspaceRepo.findFirst.mockResolvedValue({
        id: 'w1',
        enforceSso: false,
      } as any);

      await service.syncFromEnvironmentVariables();

      expect(workspaceRepo.updateWorkspace).toHaveBeenCalledWith(
        { enforceSso: true },
        'w1',
      );
    });

    it('should not update workspace when OIDC_ENFORCE is true and workspace already enforces SSO', async () => {
      process.env.OIDC_ENFORCE = 'true';
      workspaceRepo.findFirst.mockResolvedValue({
        id: 'w1',
        enforceSso: true,
      } as any);

      await service.syncFromEnvironmentVariables();

      expect(workspaceRepo.updateWorkspace).not.toHaveBeenCalled();
    });

    it('should disable SSO enforcement on workspace when OIDC_ENFORCE is false', async () => {
      process.env.OIDC_ENFORCE = 'false';
      workspaceRepo.findFirst.mockResolvedValue({
        id: 'w1',
        enforceSso: true,
      } as any);

      await service.syncFromEnvironmentVariables();

      expect(workspaceRepo.updateWorkspace).toHaveBeenCalledWith(
        { enforceSso: false },
        'w1',
      );
    });

    it('should not update workspace when OIDC_ENFORCE is not set', async () => {
      workspaceRepo.findFirst.mockResolvedValue({
        id: 'w1',
        enforceSso: false,
      } as any);

      await service.syncFromEnvironmentVariables();

      expect(workspaceRepo.updateWorkspace).not.toHaveBeenCalled();
    });
  });

  describe('syncFromEnvironmentVariables (OIDC_PROVIDER_ID)', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      process.env = { ...originalEnv };
      process.env.OIDC_ISSUER = 'https://issuer.example.com';
      process.env.OIDC_CLIENT_ID = 'cid';
      process.env.OIDC_CLIENT_SECRET = 'csecret';
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it('should use specified OIDC_PROVIDER_ID when inserting new provider', async () => {
      process.env.OIDC_PROVIDER_ID = 'custom-uuid-1234';
      workspaceRepo.findFirst.mockResolvedValue({ id: 'w1' } as any);
      authProviderRepo.findFirstByType.mockResolvedValue(undefined);

      await service.syncFromEnvironmentVariables();

      expect(authProviderRepo.insertProvider).toHaveBeenCalledWith(
        expect.objectContaining({
          id: 'custom-uuid-1234',
          name: 'OIDC',
          type: 'oidc',
        }),
      );
    });

    it('should use default deterministic fallback UUID when OIDC_PROVIDER_ID is omitted', async () => {
      delete process.env.OIDC_PROVIDER_ID;
      workspaceRepo.findFirst.mockResolvedValue({ id: 'w1' } as any);
      authProviderRepo.findFirstByType.mockResolvedValue(undefined);

      await service.syncFromEnvironmentVariables();

      expect(authProviderRepo.insertProvider).toHaveBeenCalledWith(
        expect.objectContaining({
          id: '00000000-0000-4000-8000-000000000001',
          name: 'OIDC',
          type: 'oidc',
        }),
      );
    });
  });
});
