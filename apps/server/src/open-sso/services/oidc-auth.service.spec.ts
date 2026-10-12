import { OidcAuthService } from './oidc-auth.service';
import { AuthProviderRepo } from '../repos/auth-provider.repo';
import { AuthAccountRepo } from '../repos/auth-account.repo';
import { SsoProviderService } from './sso-provider.service';
import { EnvironmentService } from '../../integrations/environment/environment.service';
import { EncryptionService } from '../../integrations/encryption/encryption.service';
import { WorkspaceRepo } from '@docmost/db/repos/workspace/workspace.repo';
import { UserRepo } from '@docmost/db/repos/user/user.repo';
import { WorkspaceService } from '../../core/workspace/services/workspace.service';
import { GroupUserRepo } from '@docmost/db/repos/group/group-user.repo';
import { GroupRepo } from '@docmost/db/repos/group/group.repo';
import { SessionService } from '../../core/session/session.service';
import { IAuditService } from '../../integrations/audit/audit.service';
import { setOpenIdClientForTesting } from './openid-loader';

describe('OidcAuthService', () => {
  let service: OidcAuthService;
  let authProviderRepo: jest.Mocked<AuthProviderRepo>;
  let authAccountRepo: jest.Mocked<AuthAccountRepo>;
  let ssoProviderService: jest.Mocked<SsoProviderService>;
  let environmentService: jest.Mocked<EnvironmentService>;
  let encryptionService: jest.Mocked<EncryptionService>;
  let workspaceRepo: jest.Mocked<WorkspaceRepo>;
  let userRepo: jest.Mocked<UserRepo>;
  let workspaceService: jest.Mocked<WorkspaceService>;
  let groupUserRepo: jest.Mocked<GroupUserRepo>;
  let groupRepo: jest.Mocked<GroupRepo>;
  let sessionService: jest.Mocked<SessionService>;
  let auditService: jest.Mocked<IAuditService>;
  let mockDb: any;
  let mockOpenIdClient: any;

  beforeEach(() => {
    authProviderRepo = {
      findEnabledById: jest.fn(),
    } as any;

    authAccountRepo = {
      findByProviderUserId: jest.fn(),
      insertAccount: jest.fn(),
    } as any;

    ssoProviderService = {
      decryptSecret: jest.fn((s) => s),
    } as any;

    environmentService = {
      getAppUrl: jest.fn(() => 'http://localhost:3000'),
    } as any;

    encryptionService = {
      encrypt: jest.fn((val: string) => `enc:${val}`),
      decrypt: jest.fn((val: string) => val.replace('enc:', '')),
    } as any;

    workspaceRepo = {
      findById: jest.fn(),
    } as any;

    userRepo = {
      findById: jest.fn(),
      findByEmail: jest.fn(),
      insertUser: jest.fn(),
      updateLastLogin: jest.fn(),
    } as any;

    workspaceService = {
      addUserToWorkspace: jest.fn(),
    } as any;

    groupUserRepo = {
      addUserToDefaultGroup: jest.fn(),
      getGroupUserById: jest.fn(),
      insertGroupUser: jest.fn(),
    } as any;

    groupRepo = {
      findByName: jest.fn(),
      insertGroup: jest.fn(),
    } as any;

    sessionService = {
      createSessionAndToken: jest.fn(),
    } as any;

    auditService = {
      log: jest.fn(),
    } as any;

    mockDb = {
      transaction: jest.fn(() => ({
        execute: jest.fn((cb) => cb(mockDb)),
      })),
    };

    mockOpenIdClient = {
      discovery: jest.fn().mockResolvedValue({} as any),
      randomPKCECodeVerifier: jest.fn().mockReturnValue('verifier'),
      calculatePKCECodeChallenge: jest.fn().mockResolvedValue('challenge'),
      randomState: jest.fn().mockReturnValue('state123'),
      randomNonce: jest.fn().mockReturnValue('nonce123'),
      buildAuthorizationUrl: jest.fn().mockReturnValue(
        new URL('https://issuer.example.com/auth?client_id=client-123&state=state123'),
      ),
      authorizationCodeGrant: jest.fn(),
      fetchUserInfo: jest.fn(),
    };

    setOpenIdClientForTesting(mockOpenIdClient);

    service = new OidcAuthService(
      authProviderRepo,
      authAccountRepo,
      ssoProviderService,
      environmentService,
      encryptionService,
      workspaceRepo,
      userRepo,
      workspaceService,
      groupUserRepo,
      groupRepo,
      sessionService,
      mockDb,
      auditService,
    );
  });

  afterEach(() => {
    setOpenIdClientForTesting(null);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('sanitizeRedirectUrl', () => {
    it('should return relative url when safe', () => {
      expect(service.sanitizeRedirectUrl('/dashboard')).toBe('/dashboard');
      expect(service.sanitizeRedirectUrl('/space/123')).toBe('/space/123');
    });

    it('should return / for malicious or external urls', () => {
      expect(service.sanitizeRedirectUrl('https://evil.com')).toBe('/');
      expect(service.sanitizeRedirectUrl('//evil.com')).toBe('/');
      expect(service.sanitizeRedirectUrl('/\\evil.com')).toBe('/');
      expect(service.sanitizeRedirectUrl('')).toBe('/');
      expect(service.sanitizeRedirectUrl(undefined)).toBe('/');
    });
  });

  describe('initiateLogin', () => {
    it('should create authorization URL and encrypted session cookie', async () => {
      authProviderRepo.findEnabledById.mockResolvedValue({
        id: 'p1',
        type: 'oidc',
        oidcIssuer: 'https://issuer.example.com',
        oidcClientId: 'client-123',
        oidcClientSecret: 'secret-456',
        workspaceId: 'w1',
      } as any);

      const result = await service.initiateLogin('p1', '/redirect-to');

      expect(result.authUrl).toContain('https://issuer.example.com/auth');
      expect(result.sessionCookie).toBeDefined();
      expect(encryptionService.encrypt).toHaveBeenCalled();
    });
  });

  describe('handleCallback', () => {
    it('should authenticate existing user with linked AuthAccount', async () => {
      const sessionState = {
        state: 'validState',
        nonce: 'validNonce',
        codeVerifier: 'verifier',
        providerId: 'p1',
        workspaceId: 'w1',
        redirect: '/custom-page',
      };
      const cookieRaw = `enc:${JSON.stringify(sessionState)}`;

      authProviderRepo.findEnabledById.mockResolvedValue({
        id: 'p1',
        type: 'oidc',
        oidcIssuer: 'https://issuer.example.com',
        oidcClientId: 'client-123',
        oidcClientSecret: 'secret-456',
        workspaceId: 'w1',
        allowSignup: true,
      } as any);

      workspaceRepo.findById.mockResolvedValue({
        id: 'w1',
        emailDomains: [],
      } as any);

      mockOpenIdClient.authorizationCodeGrant.mockResolvedValue({
        claims: () => ({
          sub: 'sub-user-1',
          email: 'user@example.com',
          name: 'Test User',
        }),
      });

      authAccountRepo.findByProviderUserId.mockResolvedValue({
        userId: 'u1',
        providerUserId: 'sub-user-1',
        authProviderId: 'p1',
      } as any);

      userRepo.findById.mockResolvedValue({
        id: 'u1',
        email: 'user@example.com',
        name: 'Test User',
        workspaceId: 'w1',
      } as any);

      sessionService.createSessionAndToken.mockResolvedValue('jwt-token-xyz');

      const result = await service.handleCallback(
        'p1',
        { code: 'authCode', state: 'validState' },
        cookieRaw,
      );

      expect(result.authToken).toBe('jwt-token-xyz');
      expect(result.redirectUrl).toBe('/custom-page');
      expect(userRepo.updateLastLogin).toHaveBeenCalledWith('u1', 'w1');
    });
  });
});
