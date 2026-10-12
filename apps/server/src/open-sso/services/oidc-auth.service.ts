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
    const config = await openidClient.discovery(
      issuerUrl,
      provider.oidcClientId,
      decryptedSecret || undefined,
    );

    const codeVerifier = openidClient.randomPKCECodeVerifier();
    const codeChallenge = await openidClient.calculatePKCECodeChallenge(codeVerifier);
    const state = openidClient.randomState();
    const nonce = openidClient.randomNonce();

    const appUrl = this.environmentService.getAppUrl();
    const redirectUri = `${appUrl}/api/sso/oidc/${provider.id}/callback`;

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
    providerId: string,
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

    if (sessionState.providerId !== providerId) {
      throw new BadRequestException('OIDC provider ID mismatch');
    }

    const provider = await this.authProviderRepo.findEnabledById(providerId);
    if (!provider || provider.type !== 'oidc') {
      throw new NotFoundException('OIDC provider not found or disabled');
    }

    const decryptedSecret = this.ssoProviderService.decryptSecret(
      provider.oidcClientSecret,
    );

    const openidClient = await loadOpenIdClient();
    const issuerUrl = new URL(provider.oidcIssuer);
    const config = await openidClient.discovery(
      issuerUrl,
      provider.oidcClientId,
      decryptedSecret || undefined,
    );

    const appUrl = this.environmentService.getAppUrl();
    const currentUrl = new URL(requestUrl || `/api/sso/oidc/${provider.id}/callback?${new URLSearchParams(query as Record<string, string>).toString()}`, appUrl);

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

    let email = claims?.email as string | undefined;
    let name = claims?.name as string | undefined;

    if (!email && tokens.access_token) {
      try {
        const userInfo = await openidClient.fetchUserInfo(
          config,
          tokens.access_token,
          sub,
        );
        email = userInfo?.email as string | undefined;
        if (!name) {
          name = userInfo?.name as string | undefined;
        }
      } catch (err: any) {
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

    // 1. Check existing AuthAccount
    const existingAccount = await this.authAccountRepo.findByProviderUserId(
      sub,
      provider.id,
    );

    let user: User;

    if (existingAccount) {
      const foundUser = await this.userRepo.findById(
        existingAccount.userId,
        workspace.id,
      );
      if (!foundUser || isUserDisabled(foundUser)) {
        throw new UnauthorizedException('User account is disabled or not found');
      }
      user = foundUser;
    } else {
      // 2. Look for existing user by email
      const existingUser = await this.userRepo.findByEmail(email, workspace.id);
      if (existingUser) {
        if (isUserDisabled(existingUser)) {
          throw new UnauthorizedException('User account is disabled');
        }
        await this.authAccountRepo.insertAccount({
          userId: existingUser.id,
          providerUserId: sub,
          authProviderId: provider.id,
          workspaceId: workspace.id,
        });
        user = existingUser;
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
              role: 'member',
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

  private async syncGroups(
    userId: string,
    workspaceId: string,
    groupsClaim: unknown,
  ): Promise<void> {
    if (!Array.isArray(groupsClaim)) {
      return;
    }

    const groupNames = groupsClaim
      .filter((g): g is string => typeof g === 'string' && g.trim().length > 0)
      .map((g) => g.trim());

    if (groupNames.length === 0) {
      return;
    }

    try {
      for (const groupName of groupNames) {
        let group = await this.groupRepo.findByName(groupName, workspaceId);
        if (!group) {
          group = await this.groupRepo.insertGroup({
            name: groupName,
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
    } catch (err: any) {
      this.logger.warn(`Group sync error: ${err.message}`);
    }
  }

  public sanitizeRedirectUrl(redirect?: string): string {
    if (!redirect) return '/';
    // Ensure relative path starting with / but not // or /\
    if (redirect.startsWith('/') && !redirect.startsWith('//') && !redirect.startsWith('/\\')) {
      return redirect;
    }
    return '/';
  }
}
