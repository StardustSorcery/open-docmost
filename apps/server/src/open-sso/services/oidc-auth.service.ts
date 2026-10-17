import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import type * as openidClientTypes from 'openid-client';
import { loadOpenIdClient } from './openid-loader';
import { randomBytes } from 'node:crypto';
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
import { validateAllowedEmail } from '../../core/auth/auth.util';
import { isUserDisabled } from '../../common/helpers';
import { getWorkspaceDefaultPageEditMode } from '../../core/workspace/workspace.util';
import { executeTx } from '@docmost/db/utils';
import { InjectKysely } from 'nestjs-kysely';
import { KyselyDB } from '@docmost/db/types/kysely.types';
import {
  AUDIT_SERVICE,
  IAuditService,
} from '../../integrations/audit/audit.service';
import { AuditEvent, AuditResource } from '../../common/events/audit-events';
import { User, Workspace } from '@docmost/db/types/entity.types';

export interface OidcSessionState {
  state: string;
  nonce: string;
  codeVerifier: string;
  providerId: string;
  workspaceId: string;
  redirect?: string;
}

@Injectable()
export class OidcAuthService {
  private readonly logger = new Logger(OidcAuthService.name);

  constructor(
    private readonly authProviderRepo: AuthProviderRepo,
    private readonly authAccountRepo: AuthAccountRepo,
    private readonly ssoProviderService: SsoProviderService,
    private readonly environmentService: EnvironmentService,
    private readonly encryptionService: EncryptionService,
    private readonly workspaceRepo: WorkspaceRepo,
    private readonly userRepo: UserRepo,
    private readonly workspaceService: WorkspaceService,
    private readonly groupUserRepo: GroupUserRepo,
    private readonly groupRepo: GroupRepo,
    private readonly sessionService: SessionService,
    @InjectKysely() private readonly db: KyselyDB,
    @Inject(AUDIT_SERVICE) private readonly auditService: IAuditService,
  ) {}

  async initiateLogin(
    providerId: string,
    redirectUrl?: string,
  ): Promise<{ authUrl: string; sessionCookie: string }> {
    const provider = await this.authProviderRepo.findEnabledById(providerId);
    if (!provider || provider.type !== 'oidc') {
      throw new NotFoundException('OIDC provider not found or disabled');
    }

    if (!provider.oidcIssuer || !provider.oidcClientId) {
      throw new BadRequestException('OIDC provider is misconfigured (missing issuer or client ID)');
    }

    const decryptedSecret = this.ssoProviderService.decryptSecret(
      provider.oidcClientSecret,
    );

    const openidClient = await loadOpenIdClient();
    const issuerUrl = new URL(provider.oidcIssuer);
    const discoveryOptions =
      issuerUrl.protocol === 'http:' && openidClient.allowInsecureRequests
        ? { execute: [openidClient.allowInsecureRequests] }
        : undefined;
    const config = await openidClient.discovery(
      issuerUrl,
      provider.oidcClientId,
      decryptedSecret || undefined,
      undefined,
      discoveryOptions,
    );

    const codeVerifier = openidClient.randomPKCECodeVerifier();
    const codeChallenge = await openidClient.calculatePKCECodeChallenge(codeVerifier);
    const state = openidClient.randomState();
    const nonce = openidClient.randomNonce();

    const appUrl = this.environmentService.getAppUrl();
    const redirectUri =
      process.env.OIDC_REDIRECT_URI ||
      `${appUrl}/api/sso/oidc/${provider.id}/callback`;

    const authUrl = openidClient.buildAuthorizationUrl(config, {
      redirect_uri: redirectUri,
      scope: 'openid email profile',
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    const sessionPayload: OidcSessionState = {
      state,
      nonce,
      codeVerifier,
      providerId: provider.id,
      workspaceId: provider.workspaceId,
      redirect: redirectUrl,
    };

    const sessionCookie = this.encryptionService.encrypt(
      JSON.stringify(sessionPayload),
    );

    return {
      authUrl: authUrl.href,
      sessionCookie,
    };
  }

  async handleCallback(
    providerId: string | undefined,
    query: { code?: string; state?: string; error?: string; error_description?: string },
    cookieRaw?: string,
    requestUrl?: string,
  ): Promise<{ authToken: string; redirectUrl: string }> {
    if (query.error) {
      this.logger.error(`OIDC IdP error: ${query.error} - ${query.error_description}`);
      throw new UnauthorizedException(query.error_description || query.error);
    }

    if (!query.code || !query.state) {
      throw new BadRequestException('Missing code or state parameter');
    }

    if (!cookieRaw) {
      throw new BadRequestException('Missing OIDC session cookie');
    }

    let sessionState: OidcSessionState;
    try {
      const decrypted = this.encryptionService.decrypt(cookieRaw);
      sessionState = JSON.parse(decrypted);
    } catch {
      throw new BadRequestException('Invalid or expired OIDC session cookie');
    }

    if (sessionState.state !== query.state) {
      throw new BadRequestException('Invalid OIDC state mismatch');
    }

    if (providerId && sessionState.providerId !== providerId) {
      throw new BadRequestException('OIDC provider ID mismatch');
    }

    const targetProviderId = providerId || sessionState.providerId;
    const provider = await this.authProviderRepo.findEnabledById(targetProviderId);
    if (!provider || provider.type !== 'oidc') {
      throw new NotFoundException('OIDC provider not found or disabled');
    }

    const decryptedSecret = this.ssoProviderService.decryptSecret(
      provider.oidcClientSecret,
    );

    const openidClient = await loadOpenIdClient();
    const issuerUrl = new URL(provider.oidcIssuer);
    const discoveryOptions =
      issuerUrl.protocol === 'http:' && openidClient.allowInsecureRequests
        ? { execute: [openidClient.allowInsecureRequests] }
        : undefined;
    const config = await openidClient.discovery(
      issuerUrl,
      provider.oidcClientId,
      decryptedSecret || undefined,
      undefined,
      discoveryOptions,
    );

    const appUrl = this.environmentService.getAppUrl();
    const callbackPath = process.env.OIDC_REDIRECT_URI
      ? new URL(process.env.OIDC_REDIRECT_URI, appUrl).pathname
      : `/api/sso/oidc/${provider.id}/callback`;
    const searchParams = new URLSearchParams(query as Record<string, string>).toString();
    const currentUrl = new URL(`${callbackPath}?${searchParams}`, appUrl);

    let tokens: openidClientTypes.TokenEndpointResponse & openidClientTypes.TokenEndpointResponseHelpers;
    try {
      tokens = await openidClient.authorizationCodeGrant(config, currentUrl, {
        pkceCodeVerifier: sessionState.codeVerifier,
        expectedState: sessionState.state,
        expectedNonce: sessionState.nonce,
      });
    } catch (err: any) {
      this.logger.error('Failed to exchange code for tokens', err);
      throw new UnauthorizedException(`OIDC token exchange failed: ${err.message}`);
    }

    const claims = tokens.claims();
    const sub = claims?.sub;
    if (!sub) {
      throw new UnauthorizedException('OIDC token did not contain sub claim');
    }

    const emailVerified = claims?.email_verified;
    if (emailVerified === false || (emailVerified as any) === 'false') {
      throw new UnauthorizedException('Email address is not verified by OIDC provider');
    }

    let email = claims?.email as string | undefined;
    let name = claims?.name as string | undefined;

    if (!email && tokens.access_token) {
      try {
        const userInfo = await openidClient.fetchUserInfo(
          config,
          tokens.access_token,
          sub,
        );
        const userInfoEmailVerified = userInfo?.email_verified;
        if (
          userInfoEmailVerified === false ||
          (userInfoEmailVerified as any) === 'false'
        ) {
          throw new UnauthorizedException(
            'Email address is not verified by OIDC provider',
          );
        }
        email = userInfo?.email as string | undefined;
        if (!name) {
          name = userInfo?.name as string | undefined;
        }
      } catch (err: any) {
        if (err instanceof UnauthorizedException) {
          throw err;
        }
        this.logger.warn(`Failed to fetch userInfo: ${err.message}`);
      }
    }

    if (!email) {
      throw new UnauthorizedException('Could not retrieve email from OIDC provider');
    }

    if (!name) {
      name =
        (claims?.preferred_username as string) ||
        (claims?.nickname as string) ||
        email.split('@')[0];
    }

    const workspace = await this.workspaceRepo.findById(sessionState.workspaceId);
    if (!workspace) {
      throw new NotFoundException('Workspace not found');
    }

    validateAllowedEmail(email, workspace);

    // Evaluate Role Mappings and enforce access control if configured
    const roleMappings = this.getRoleMappings();
    let assignedRole: 'admin' | 'member' = 'member';

    if (roleMappings) {
      const determinedRole = this.determineRole(claims?.groups, roleMappings);
      if (!determinedRole) {
        throw new ForbiddenException(
          'Access denied: user does not belong to any authorized groups',
        );
      }
      assignedRole = determinedRole;
    }

    // 1. Look for existing user by email (email is the primary unique key)
    const existingUser = await this.userRepo.findByEmail(
      email.toLowerCase(),
      workspace.id,
    );

    let user: User;

    if (existingUser) {
      if (isUserDisabled(existingUser)) {
        throw new UnauthorizedException('User account is disabled');
      }
      user = existingUser;

      // Link AuthAccount if not linked yet
      const linkedAccount = await this.authAccountRepo.findByProviderUserId(
        sub,
        provider.id,
      );
      if (!linkedAccount) {
        await this.authAccountRepo.insertAccount({
          userId: user.id,
          providerUserId: sub,
          authProviderId: provider.id,
          workspaceId: workspace.id,
        });
      }

      const updateData: Record<string, any> = {};
      if (!user.emailVerifiedAt) {
        updateData.emailVerifiedAt = new Date();
      }
      if (!user.name && name) {
        updateData.name = name;
        user.name = name;
      }
      if (Object.keys(updateData).length > 0) {
        await this.userRepo.updateUser(updateData, user.id, workspace.id);
      }
    } else {
      // 2. Check existing AuthAccount by providerUserId as fallback
      const existingAccount = await this.authAccountRepo.findByProviderUserId(
        sub,
        provider.id,
      );

      if (existingAccount) {
        const foundUser = await this.userRepo.findById(
          existingAccount.userId,
          workspace.id,
        );
        if (!foundUser || isUserDisabled(foundUser)) {
          throw new UnauthorizedException('User account is disabled or not found');
        }
        user = foundUser;

        if (!user.name && name) {
          await this.userRepo.updateUser({ name }, user.id, workspace.id);
          user.name = name;
        }
      } else {
        // 3. Register new user
        if (!provider.allowSignup) {
          throw new ForbiddenException(
            'Sign-up is not allowed for this OIDC provider. Please contact your workspace administrator.',
          );
        }

        const generatedPassword = randomBytes(32).toString('hex');
        user = await executeTx(this.db, async (trx) => {
          const newUser = await this.userRepo.insertUser(
            {
              name,
              email: email.toLowerCase(),
              password: generatedPassword,
              role: assignedRole,
              workspaceId: workspace.id,
              emailVerifiedAt: new Date(),
              hasGeneratedPassword: false,
            },
            trx,
            { pageEditMode: getWorkspaceDefaultPageEditMode(workspace) },
          );

          await this.workspaceService.addUserToWorkspace(
            newUser.id,
            workspace.id,
            undefined,
            trx,
          );

          await this.groupUserRepo.addUserToDefaultGroup(
            newUser.id,
            workspace.id,
            trx,
          );

          await this.authAccountRepo.insertAccount(
            {
              userId: newUser.id,
              providerUserId: sub,
              authProviderId: provider.id,
              workspaceId: workspace.id,
            },
            trx,
          );

          return newUser;
        });

        this.auditService.log({
          event: AuditEvent.USER_CREATED,
          resourceType: AuditResource.USER,
          resourceId: user.id,
          changes: {
            after: {
              name: user.name,
              email: user.email,
              role: user.role,
            },
          },
          metadata: {
            source: 'oidc',
            providerId: provider.id,
          },
        });
      }
    }

    // Sync role for existing user if roleMappings is configured (protect workspace owner)
    if (roleMappings && user.role !== 'owner' && user.role !== assignedRole) {
      await this.userRepo.updateUser({ role: assignedRole }, user.id, workspace.id);
      this.auditService.log({
        event: AuditEvent.USER_ROLE_CHANGED,
        resourceType: AuditResource.USER,
        resourceId: user.id,
        changes: {
          before: { role: user.role },
          after: { role: assignedRole },
        },
        metadata: {
          source: 'oidc',
          providerId: provider.id,
        },
      });
      user.role = assignedRole;
    }

    // 4. Group Sync if enabled
    if (provider.groupSync) {
      await this.syncGroups(user.id, workspace.id, claims?.groups);
    }

    // 5. Create Session & Token
    const authToken = await this.sessionService.createSessionAndToken(user);
    await this.userRepo.updateLastLogin(user.id, workspace.id);

    this.auditService.log({
      event: AuditEvent.USER_LOGIN,
      resourceType: AuditResource.USER,
      resourceId: user.id,
      metadata: { source: 'oidc', providerId: provider.id },
    });

    const safeRedirect = this.sanitizeRedirectUrl(sessionState.redirect);

    return {
      authToken,
      redirectUrl: safeRedirect,
    };
  }

  public getRoleMappings(): {
    adminGroups: Set<string>;
    memberGroups: Set<string>;
  } | null {
    const raw = process.env.OIDC_ROLE_MAPPINGS;
    if (!raw || !raw.trim()) {
      return null;
    }

    const adminGroups = new Set<string>();
    const memberGroups = new Set<string>();

    const addMapping = (group: string, role: string) => {
      const cleanGroup = group.trim().toLowerCase();
      const cleanRole = role.trim().toLowerCase();
      if (!cleanGroup) return;
      if (cleanRole === 'admin') {
        adminGroups.add(cleanGroup);
      } else if (cleanRole === 'member') {
        memberGroups.add(cleanGroup);
      }
    };

    try {
      if (raw.trim().startsWith('{')) {
        const parsed = JSON.parse(raw);
        for (const [key, value] of Object.entries(parsed)) {
          const lowerKey = key.trim().toLowerCase();
          if (lowerKey === 'admin' || lowerKey === 'member') {
            // key is role, value is array of groups or a single group
            if (Array.isArray(value)) {
              for (const item of value) {
                if (typeof item === 'string') {
                  addMapping(item, lowerKey);
                }
              }
            } else if (typeof value === 'string') {
              addMapping(value, lowerKey);
            }
          } else if (typeof value === 'string') {
            // key is group, value is role
            addMapping(key, value);
          }
        }
        return { adminGroups, memberGroups };
      }
    } catch (err: any) {
      this.logger.warn(`Failed to parse OIDC_ROLE_MAPPINGS as JSON: ${err.message}`);
    }

    // Fallback: comma-separated pairs
    const pairs = raw.split(',');
    for (const pair of pairs) {
      const trimmed = pair.trim();
      if (!trimmed) continue;

      const lastColon = trimmed.lastIndexOf(':');
      const firstColon = trimmed.indexOf(':');

      if (lastColon !== -1) {
        const afterLast = trimmed.substring(lastColon + 1).trim().toLowerCase();
        const beforeLast = trimmed.substring(0, lastColon).trim();

        if (afterLast === 'admin' || afterLast === 'member') {
          addMapping(beforeLast, afterLast);
          continue;
        }

        const beforeFirst = trimmed.substring(0, firstColon).trim().toLowerCase();
        const afterFirst = trimmed.substring(firstColon + 1).trim();
        if (beforeFirst === 'admin' || beforeFirst === 'member') {
          addMapping(afterFirst, beforeFirst);
          continue;
        }
      }
    }

    return { adminGroups, memberGroups };
  }

  public determineRole(
    groupsClaim: unknown,
    roleMappings: { adminGroups: Set<string>; memberGroups: Set<string> },
  ): 'admin' | 'member' | null {
    const userGroups = new Set<string>();
    if (Array.isArray(groupsClaim)) {
      for (const g of groupsClaim) {
        if (typeof g === 'string' && g.trim()) {
          userGroups.add(g.trim().toLowerCase());
        }
      }
    }

    // Check admin groups first for higher privilege
    for (const adminGroup of roleMappings.adminGroups) {
      if (userGroups.has(adminGroup)) {
        return 'admin';
      }
    }

    // Check member groups
    for (const memberGroup of roleMappings.memberGroups) {
      if (userGroups.has(memberGroup)) {
        return 'member';
      }
    }

    return null;
  }

  private getGroupMappings(): Map<string, string> {
    const raw = process.env.OIDC_GROUP_MAPPINGS;
    const mapping = new Map<string, string>();
    if (!raw || !raw.trim()) {
      return mapping;
    }
    try {
      if (raw.trim().startsWith('{')) {
        const parsed = JSON.parse(raw);
        for (const [idpGroup, docmostGroup] of Object.entries(parsed)) {
          if (typeof docmostGroup === 'string') {
            mapping.set(idpGroup.trim().toLowerCase(), docmostGroup.trim());
          }
        }
        return mapping;
      }
    } catch (err: any) {
      this.logger.warn(`Failed to parse OIDC_GROUP_MAPPINGS as JSON: ${err.message}`);
    }

    // Fallback: comma-separated key:value
    const pairs = raw.split(',');
    for (const pair of pairs) {
      const [k, v] = pair.split(':');
      if (k && v) {
        mapping.set(k.trim().toLowerCase(), v.trim());
      }
    }
    return mapping;
  }

  private async syncGroups(
    userId: string,
    workspaceId: string,
    groupsClaim: unknown,
  ): Promise<void> {
    if (!Array.isArray(groupsClaim)) {
      return;
    }

    const mappings = this.getGroupMappings();
    // If no mappings are configured, ignore all external groups per requirements
    if (mappings.size === 0) {
      return;
    }

    const incomingIdpGroups = new Set(
      groupsClaim
        .filter((g): g is string => typeof g === 'string' && g.trim().length > 0)
        .map((g) => g.trim().toLowerCase()),
    );

    // Determine target Docmost group names to grant (ignore unmapped groups)
    const targetDocmostGroupNames = new Set<string>();
    for (const idpGroup of incomingIdpGroups) {
      const mappedDocmostName = mappings.get(idpGroup);
      if (mappedDocmostName) {
        targetDocmostGroupNames.add(mappedDocmostName);
      }
    }

    // All Docmost group names managed by this OIDC mapping
    const allManagedDocmostGroupNames = Array.from(mappings.values());

    try {
      // 1. Grant mapped groups
      for (const docmostGroupName of targetDocmostGroupNames) {
        let group = await this.groupRepo.findByName(docmostGroupName, workspaceId);
        if (!group) {
          group = await this.groupRepo.insertGroup({
            name: docmostGroupName,
            isDefault: false,
            isExternal: true,
            workspaceId,
          });
        }

        const existingMembership = await this.groupUserRepo.getGroupUserById(
          userId,
          group.id,
        );

        if (!existingMembership) {
          await this.groupUserRepo.insertGroupUser({
            userId,
            groupId: group.id,
          });
        }
      }

      // 2. Revoke unassigned managed groups
      const userGroupIds = await this.groupUserRepo.getUserGroupIds(userId);
      for (const groupId of userGroupIds) {
        const group = await this.groupRepo.findById(groupId, workspaceId);
        if (!group || group.isDefault) {
          continue; // Protect default group (e.g. Everyone)
        }

        const isManaged = allManagedDocmostGroupNames.some(
          (name) => name.toLowerCase() === group.name.toLowerCase(),
        );
        const shouldKeep = Array.from(targetDocmostGroupNames).some(
          (name) => name.toLowerCase() === group.name.toLowerCase(),
        );

        if (isManaged && !shouldKeep) {
          await this.groupUserRepo.delete(userId, group.id);
        }
      }
    } catch (err: any) {
      this.logger.warn(`Group sync error: ${err.message}`);
    }
  }

  public sanitizeRedirectUrl(redirect?: string): string {
    if (!redirect) return '/';
    // Reject protocol-relative or backslash-based paths
    if (redirect.startsWith('//') || redirect.startsWith('/\\')) {
      return '/';
    }
    try {
      const appUrl = new URL(this.environmentService.getAppUrl());
      const parsed = new URL(redirect, appUrl);
      if (
        parsed.origin === appUrl.origin &&
        (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
        !parsed.pathname.startsWith('//') &&
        !parsed.pathname.startsWith('/\\')
      ) {
        return parsed.pathname + parsed.search + parsed.hash;
      }
    } catch {
      // ignore
    }
    return '/';
  }
}
