import { SsoManagementController } from './sso-management.controller';
import { SsoProviderService } from '../services/sso-provider.service';
import WorkspaceAbilityFactory from '../../core/casl/abilities/workspace-ability.factory';

describe('SsoManagementController', () => {
  let controller: SsoManagementController;
  let ssoProviderService: jest.Mocked<SsoProviderService>;
  let workspaceAbility: jest.Mocked<WorkspaceAbilityFactory>;

  const mockUser: any = { id: 'u1', role: 'admin' };
  const mockWorkspace: any = { id: 'w1' };

  beforeEach(() => {
    ssoProviderService = {
      getProviders: jest.fn(),
      createProvider: jest.fn(),
      updateProvider: jest.fn(),
      deleteProvider: jest.fn(),
      getProviderById: jest.fn(),
    } as any;

    workspaceAbility = {
      createForUser: jest.fn().mockReturnValue({
        cannot: jest.fn().mockReturnValue(false),
        can: jest.fn().mockReturnValue(true),
      }),
    } as any;

    controller = new SsoManagementController(
      ssoProviderService,
      workspaceAbility,
    );
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('getProviders', () => {
    it('should return list of providers', async () => {
      ssoProviderService.getProviders.mockResolvedValue([
        { id: 'p1', name: 'Google' } as any,
      ]);

      const result = await controller.getProviders(mockWorkspace, mockUser);
      expect(result).toEqual({
        items: [{ id: 'p1', name: 'Google' }],
      });
    });
  });

  describe('createProvider', () => {
    it('should create new provider', async () => {
      ssoProviderService.createProvider.mockResolvedValue({
        id: 'p1',
        name: 'OIDC',
        type: 'oidc',
      } as any);

      const result = await controller.createProvider(
        mockWorkspace,
        mockUser,
        { name: 'OIDC', type: 'oidc' },
      );

      expect(ssoProviderService.createProvider).toHaveBeenCalledWith(
        { name: 'OIDC', type: 'oidc' },
        'w1',
        'u1',
      );
      expect(result.id).toBe('p1');
    });
  });

  describe('updateProvider', () => {
    it('should update provider', async () => {
      ssoProviderService.updateProvider.mockResolvedValue({
        id: 'p1',
        name: 'New Name',
      } as any);

      const result = await controller.updateProvider(
        mockWorkspace,
        mockUser,
        { providerId: 'p1', name: 'New Name' },
      );

      expect(result.name).toBe('New Name');
    });
  });

  describe('deleteProvider', () => {
    it('should delete provider and return success', async () => {
      ssoProviderService.deleteProvider.mockResolvedValue(undefined);

      const result = await controller.deleteProvider(
        mockWorkspace,
        mockUser,
        { providerId: 'p1' },
      );

      expect(result).toEqual({ success: true });
    });
  });
});
