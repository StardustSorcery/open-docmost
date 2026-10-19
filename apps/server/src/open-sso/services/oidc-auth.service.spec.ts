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
      updateUser: jest.fn(),
      updateLastLogin: jest.fn(),
    } as any;

    workspaceService = {
      addUserToWorkspace: jest.fn(),
    } as any;

    groupUserRepo = {
      addUserToDefaultGroup: jest.fn(),
      getGroupUserById: jest.fn(),
      insertGroupUser: jest.fn(),
      delete: jest.fn(),
      getUserGroupIds: jest.fn(),
    } as any;

    groupRepo = {
      findByName: jest.fn(),
      findById: jest.fn(),
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
      allowInsecureRequests: jest.fn(),
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
      expect(service.sanitizeRedirectUrl('/\\/evil.com')).toBe('/');
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

    it('should reject authentication if email_verified is explicitly false', async () => {
      const sessionState = {
        state: 'validState',
        nonce: 'validNonce',
        codeVerifier: 'verifier',
        providerId: 'p1',
        workspaceId: 'w1',
      };
      const cookieRaw = `enc:${JSON.stringify(sessionState)}`;

      authProviderRepo.findEnabledById.mockResolvedValue({
        id: 'p1',
        type: 'oidc',
        oidcIssuer: 'https://issuer.example.com',
        oidcClientId: 'client-123',
        oidcClientSecret: 'secret-456',
        workspaceId: 'w1',
      } as any);

      workspaceRepo.findById.mockResolvedValue({
        id: 'w1',
        emailDomains: [],
      } as any);

      mockOpenIdClient.authorizationCodeGrant.mockResolvedValue({
        claims: () => ({
          sub: 'sub-user-1',
          email: 'unverified@example.com',
          email_verified: false,
        }),
      });

      await expect(
        service.handleCallback(
          'p1',
          { code: 'authCode', state: 'validState' },
          cookieRaw,
        ),
      ).rejects.toThrow('Email address is not verified');
    });

    it('should link existing user by email if AuthAccount not yet linked', async () => {
      const sessionState = {
        state: 'validState',
        nonce: 'validNonce',
        codeVerifier: 'verifier',
        providerId: 'p1',
        workspaceId: 'w1',
      };
      const cookieRaw = `enc:${JSON.stringify(sessionState)}`;

      authProviderRepo.findEnabledById.mockResolvedValue({
        id: 'p1',
        type: 'oidc',
        oidcIssuer: 'https://issuer.example.com',
        oidcClientId: 'client-123',
        oidcClientSecret: 'secret-456',
        workspaceId: 'w1',
      } as any);

      workspaceRepo.findById.mockResolvedValue({
        id: 'w1',
        emailDomains: [],
      } as any);

      mockOpenIdClient.authorizationCodeGrant.mockResolvedValue({
        claims: () => ({
          sub: 'sub-user-2',
          email: 'existing@example.com',
          email_verified: true,
        }),
      });

      authAccountRepo.findByProviderUserId.mockResolvedValue(undefined);
      userRepo.findByEmail.mockResolvedValue({
        id: 'u2',
        email: 'existing@example.com',
        name: 'Existing User',
        workspaceId: 'w1',
      } as any);

      sessionService.createSessionAndToken.mockResolvedValue('jwt-token-existing');

      const result = await service.handleCallback(
        'p1',
        { code: 'authCode', state: 'validState' },
        cookieRaw,
      );

      expect(result.authToken).toBe('jwt-token-existing');
      expect(authAccountRepo.insertAccount).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'u2',
          providerUserId: 'sub-user-2',
          authProviderId: 'p1',
          workspaceId: 'w1',
        }),
      );
    });

    it('should update user name from OIDC claims if existing user has no name', async () => {
      const sessionState = {
        state: 'validState',
        nonce: 'validNonce',
        codeVerifier: 'verifier',
        providerId: 'p1',
        workspaceId: 'w1',
      };
      const cookieRaw = `enc:${JSON.stringify(sessionState)}`;

      authProviderRepo.findEnabledById.mockResolvedValue({
        id: 'p1',
        type: 'oidc',
        oidcIssuer: 'https://issuer.example.com',
        oidcClientId: 'client-123',
        oidcClientSecret: 'secret-456',
        workspaceId: 'w1',
      } as any);

      workspaceRepo.findById.mockResolvedValue({
        id: 'w1',
        emailDomains: [],
      } as any);

      mockOpenIdClient.authorizationCodeGrant.mockResolvedValue({
        claims: () => ({
          sub: 'sub-user-3',
          email: 'admin@example.com',
          name: 'OIDC Admin Name',
          email_verified: true,
        }),
      });

      authAccountRepo.findByProviderUserId.mockResolvedValue(undefined);
      userRepo.findByEmail.mockResolvedValue({
        id: 'u3',
        email: 'admin@example.com',
        name: null,
        workspaceId: 'w1',
        emailVerifiedAt: new Date(),
      } as any);

      sessionService.createSessionAndToken.mockResolvedValue('jwt-token-admin');

      await service.handleCallback(
        'p1',
        { code: 'authCode', state: 'validState' },
        cookieRaw,
      );

      expect(userRepo.updateUser).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'OIDC Admin Name' }),
        'u3',
        'w1',
      );
    });

    it('should not overwrite existing user name if user already has a name', async () => {
      const sessionState = {
        state: 'validState',
        nonce: 'validNonce',
        codeVerifier: 'verifier',
        providerId: 'p1',
        workspaceId: 'w1',
      };
      const cookieRaw = `enc:${JSON.stringify(sessionState)}`;

      authProviderRepo.findEnabledById.mockResolvedValue({
        id: 'p1',
        type: 'oidc',
        oidcIssuer: 'https://issuer.example.com',
        oidcClientId: 'client-123',
        oidcClientSecret: 'secret-456',
        workspaceId: 'w1',
      } as any);

      workspaceRepo.findById.mockResolvedValue({
        id: 'w1',
        emailDomains: [],
      } as any);

      mockOpenIdClient.authorizationCodeGrant.mockResolvedValue({
        claims: () => ({
          sub: 'sub-user-4',
          email: 'custom@example.com',
          name: 'OIDC Claim Name',
          email_verified: true,
        }),
      });

      authAccountRepo.findByProviderUserId.mockResolvedValue(undefined);
      userRepo.findByEmail.mockResolvedValue({
        id: 'u4',
        email: 'custom@example.com',
        name: 'Explicit Custom Name',
        workspaceId: 'w1',
        emailVerifiedAt: new Date(),
      } as any);

      sessionService.createSessionAndToken.mockResolvedValue('jwt-token-custom');

      await service.handleCallback(
        'p1',
        { code: 'authCode', state: 'validState' },
        cookieRaw,
      );

      expect(userRepo.updateUser).not.toHaveBeenCalledWith(
        expect.objectContaining({ name: expect.anything() }),
        'u4',
        'w1',
      );
    });

    describe('group sync (RBAC)', () => {
      const originalEnv = process.env.OIDC_GROUP_MAPPINGS;

      beforeEach(() => {
        // IdP group 'idp-admin' maps to Docmost 'Admins', 'idp-dev' maps to 'Developers'
        process.env.OIDC_GROUP_MAPPINGS = JSON.stringify({
          'idp-admin': 'Admins',
          'idp-dev': 'Developers',
        });
      });

      afterEach(() => {
        process.env.OIDC_GROUP_MAPPINGS = originalEnv;
      });

      it('should grant mapped groups, ignore unmapped groups, and revoke unassigned mapped groups', async () => {
        const sessionState = {
          state: 'validState',
          nonce: 'validNonce',
          codeVerifier: 'verifier',
          providerId: 'p1',
          workspaceId: 'w1',
        };
        const cookieRaw = `enc:${JSON.stringify(sessionState)}`;

        authProviderRepo.findEnabledById.mockResolvedValue({
          id: 'p1',
          type: 'oidc',
          oidcIssuer: 'https://issuer.example.com',
          oidcClientId: 'client-123',
          oidcClientSecret: 'secret-456',
          workspaceId: 'w1',
          groupSync: true,
        } as any);

        workspaceRepo.findById.mockResolvedValue({
          id: 'w1',
          emailDomains: [],
        } as any);

        // IdP claims has 'idp-admin' and 'unknown-group' (should be ignored).
        // It does NOT have 'idp-dev' (should be revoked if user currently has it).
        mockOpenIdClient.authorizationCodeGrant.mockResolvedValue({
          claims: () => ({
            sub: 'sub-user-1',
            email: 'user@example.com',
            email_verified: true,
            groups: ['idp-admin', 'unknown-group'],
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

        const adminGroup = { id: 'g-admin', name: 'Admins', isDefault: false, isExternal: true, workspaceId: 'w1' };
        const devGroup = { id: 'g-dev', name: 'Developers', isDefault: false, isExternal: true, workspaceId: 'w1' };
        const defaultGroup = { id: 'g-everyone', name: 'Everyone', isDefault: true, workspaceId: 'w1' };

        groupRepo.findByName.mockImplementation(async (name: string) => {
          if (name.toLowerCase() === 'admins') return adminGroup as any;
          if (name.toLowerCase() === 'developers') return devGroup as any;
          return undefined;
        });

        groupRepo.findById.mockImplementation(async (id: string) => {
          if (id === 'g-admin') return adminGroup as any;
          if (id === 'g-dev') return devGroup as any;
          if (id === 'g-everyone') return defaultGroup as any;
          return undefined;
        });

        // User currently belongs to Developers ('g-dev') and Everyone ('g-everyone')
        groupUserRepo.getUserGroupIds.mockResolvedValue(['g-dev', 'g-everyone']);
        groupUserRepo.getGroupUserById.mockImplementation(async (userId, groupId) => {
          if (groupId === 'g-dev') return { userId, groupId } as any;
          return undefined;
        });

        sessionService.createSessionAndToken.mockResolvedValue('jwt-token-xyz');

        await service.handleCallback(
          'p1',
          { code: 'authCode', state: 'validState' },
          cookieRaw,
        );

        // 1. Should grant 'Admins' group
        expect(groupUserRepo.insertGroupUser).toHaveBeenCalledWith({
          userId: 'u1',
          groupId: 'g-admin',
        });

        // 2. Should ignore 'unknown-group' (never create or find it)
        expect(groupRepo.insertGroup).not.toHaveBeenCalledWith(
          expect.objectContaining({ name: 'unknown-group' }),
        );

        // 3. Should revoke 'Developers' group because it was not in the claim
        expect(groupUserRepo.delete).toHaveBeenCalledWith('u1', 'g-dev');

        // 4. Must NOT revoke default group 'Everyone'
        expect(groupUserRepo.delete).not.toHaveBeenCalledWith('u1', 'g-everyone');
      });
    });

    describe('OIDC_ROLE_MAPPINGS & Access Control', () => {
      const originalRoleEnv = process.env.OIDC_ROLE_MAPPINGS;

      afterEach(() => {
        if (originalRoleEnv !== undefined) {
          process.env.OIDC_ROLE_MAPPINGS = originalRoleEnv;
        } else {
          delete process.env.OIDC_ROLE_MAPPINGS;
        }
      });

      it('should parse JSON role mapping with roles as keys', () => {
        process.env.OIDC_ROLE_MAPPINGS = JSON.stringify({
          admin: ['cosmos:note-dev:admin'],
          member: ['cosmos:note-dev:general-user'],
        });
        const mapping = service.getRoleMappings();
        expect(mapping).not.toBeNull();
        expect(mapping?.adminGroups.has('cosmos:note-dev:admin')).toBe(true);
        expect(mapping?.memberGroups.has('cosmos:note-dev:general-user')).toBe(true);
      });

      it('should parse JSON role mapping with groups as keys', () => {
        process.env.OIDC_ROLE_MAPPINGS = JSON.stringify({
          'cosmos:note-dev:admin': 'admin',
          'cosmos:note-dev:general-user': 'member',
        });
        const mapping = service.getRoleMappings();
        expect(mapping).not.toBeNull();
        expect(mapping?.adminGroups.has('cosmos:note-dev:admin')).toBe(true);
        expect(mapping?.memberGroups.has('cosmos:note-dev:general-user')).toBe(true);
      });

      it('should parse comma-separated role mappings', () => {
        process.env.OIDC_ROLE_MAPPINGS =
          'cosmos:note-dev:admin:admin,cosmos:note-dev:general-user:member';
        const mapping = service.getRoleMappings();
        expect(mapping).not.toBeNull();
        expect(mapping?.adminGroups.has('cosmos:note-dev:admin')).toBe(true);
        expect(mapping?.memberGroups.has('cosmos:note-dev:general-user')).toBe(true);
      });

      it('should return null when OIDC_ROLE_MAPPINGS is not set', () => {
        delete process.env.OIDC_ROLE_MAPPINGS;
        expect(service.getRoleMappings()).toBeNull();
      });

      it('determineRole should prioritize admin over member', () => {
        const mappings = {
          adminGroups: new Set(['cosmos:admin']),
          memberGroups: new Set(['cosmos:user']),
        };
        expect(service.determineRole(['cosmos:admin', 'cosmos:user'], mappings)).toBe('admin');
        expect(service.determineRole(['cosmos:user'], mappings)).toBe('member');
        expect(service.determineRole(['cosmos:other'], mappings)).toBeNull();
      });

      it('should block access with ForbiddenException when user does not have any mapped group', async () => {
        process.env.OIDC_ROLE_MAPPINGS = JSON.stringify({
          admin: ['cosmos:note-dev:admin'],
          member: ['cosmos:note-dev:general-user'],
        });

        const sessionState = {
          state: 'validState',
          nonce: 'validNonce',
          codeVerifier: 'verifier',
          providerId: 'p1',
          workspaceId: 'w1',
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
            sub: 'sub-unauthorized-user',
            email: 'unauthorized@example.com',
            name: 'Unauthorized User',
            email_verified: true,
            groups: ['other-unrelated-group'],
          }),
        });

        await expect(
          service.handleCallback(
            'p1',
            { code: 'authCode', state: 'validState' },
            cookieRaw,
          ),
        ).rejects.toThrow('Access denied: user does not belong to any authorized groups');
      });

      it('should create new user with admin role when matching admin group', async () => {
        process.env.OIDC_ROLE_MAPPINGS = JSON.stringify({
          admin: ['cosmos:note-dev:admin'],
          member: ['cosmos:note-dev:general-user'],
        });

        const sessionState = {
          state: 'validState',
          nonce: 'validNonce',
          codeVerifier: 'verifier',
          providerId: 'p1',
          workspaceId: 'w1',
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
            sub: 'sub-admin-user',
            email: 'admin-user@example.com',
            name: 'Admin User',
            email_verified: true,
            groups: ['cosmos:note-dev:admin'],
          }),
        });

        authAccountRepo.findByProviderUserId.mockResolvedValue(undefined);
        userRepo.findByEmail.mockResolvedValue(undefined);
        userRepo.insertUser.mockResolvedValue({
          id: 'u-admin',
          email: 'admin-user@example.com',
          role: 'admin',
          workspaceId: 'w1',
        } as any);
        sessionService.createSessionAndToken.mockResolvedValue('jwt-token-admin');

        await service.handleCallback(
          'p1',
          { code: 'authCode', state: 'validState' },
          cookieRaw,
        );

        expect(userRepo.insertUser).toHaveBeenCalledWith(
          expect.objectContaining({
            email: 'admin-user@example.com',
            role: 'admin',
          }),
          expect.anything(),
          expect.anything(),
        );
      });

      it('should update existing member user to admin role when matching admin group', async () => {
        process.env.OIDC_ROLE_MAPPINGS = JSON.stringify({
          admin: ['cosmos:note-dev:admin'],
          member: ['cosmos:note-dev:general-user'],
        });

        const sessionState = {
          state: 'validState',
          nonce: 'validNonce',
          codeVerifier: 'verifier',
          providerId: 'p1',
          workspaceId: 'w1',
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
            sub: 'sub-existing-user',
            email: 'existing@example.com',
            name: 'Existing User',
            email_verified: true,
            groups: ['cosmos:note-dev:admin'],
          }),
        });

        authAccountRepo.findByProviderUserId.mockResolvedValue({ id: 'acc1', userId: 'u-existing' } as any);
        userRepo.findByEmail.mockResolvedValue({
          id: 'u-existing',
          email: 'existing@example.com',
          role: 'member',
          workspaceId: 'w1',
          emailVerifiedAt: new Date(),
        } as any);
        sessionService.createSessionAndToken.mockResolvedValue('jwt-token-updated');

        await service.handleCallback(
          'p1',
          { code: 'authCode', state: 'validState' },
          cookieRaw,
        );

        expect(userRepo.updateUser).toHaveBeenCalledWith(
          { role: 'admin' },
          'u-existing',
          'w1',
        );
        expect(auditService.log).toHaveBeenCalledWith(
          expect.objectContaining({
            event: 'user.role_changed',
            resourceId: 'u-existing',
            changes: {
              before: { role: 'member' },
              after: { role: 'admin' },
            },
          }),
        );
      });

      it('should protect workspace owner from role changes', async () => {
        process.env.OIDC_ROLE_MAPPINGS = JSON.stringify({
          admin: ['cosmos:note-dev:admin'],
          member: ['cosmos:note-dev:general-user'],
        });

        const sessionState = {
          state: 'validState',
          nonce: 'validNonce',
          codeVerifier: 'verifier',
          providerId: 'p1',
          workspaceId: 'w1',
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
            sub: 'sub-owner-user',
            email: 'owner@example.com',
            name: 'Owner User',
            email_verified: true,
            groups: ['cosmos:note-dev:general-user'],
          }),
        });

        authAccountRepo.findByProviderUserId.mockResolvedValue({ id: 'acc-owner', userId: 'u-owner' } as any);
        userRepo.findByEmail.mockResolvedValue({
          id: 'u-owner',
          email: 'owner@example.com',
          role: 'owner',
          workspaceId: 'w1',
          emailVerifiedAt: new Date(),
        } as any);
        sessionService.createSessionAndToken.mockResolvedValue('jwt-token-owner');

        await service.handleCallback(
          'p1',
          { code: 'authCode', state: 'validState' },
          cookieRaw,
        );

        // Should NOT update role when user is owner
        expect(userRepo.updateUser).not.toHaveBeenCalledWith(
          expect.objectContaining({ role: expect.anything() }),
          'u-owner',
          'w1',
        );
      });
    });
  });
});

