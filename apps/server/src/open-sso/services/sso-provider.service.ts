import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
  OnApplicationBootstrap,
} from '@nestjs/common';
import { AuthProviderRepo } from '../repos/auth-provider.repo';
import { EncryptionService } from '../../integrations/encryption/encryption.service';
import { CreateSsoProviderDto } from '../dto/create-sso-provider.dto';
import { UpdateSsoProviderDto } from '../dto/update-sso-provider.dto';
import { AuthProvider, Workspace } from '@docmost/db/types/entity.types';
import { WorkspaceRepo } from '@docmost/db/repos/workspace/workspace.repo';

@Injectable()
export class SsoProviderService implements OnApplicationBootstrap {
  private readonly logger = new Logger(SsoProviderService.name);

  constructor(
    private readonly authProviderRepo: AuthProviderRepo,
    private readonly encryptionService: EncryptionService,
    private readonly workspaceRepo: WorkspaceRepo,
  ) {}

  async onApplicationBootstrap() {
    await this.syncFromEnvironmentVariables();
  }

  async syncFromEnvironmentVariables() {
    try {
      const workspace = await this.workspaceRepo.findFirst();
      if (!workspace) {
        return;
      }

      await this.syncOidcEnforce(workspace);
      await this.syncOidcProvider(workspace);
    } catch (err: any) {
      this.logger.warn(
        `Failed to sync OIDC configuration from environment variables: ${err.message}`,
      );
    }
  }

  private async syncOidcEnforce(workspace: Workspace) {
    if (process.env.OIDC_ENFORCE === 'true') {
      if (!workspace.enforceSso) {
        this.logger.log(`Enforcing SSO for workspace: ${workspace.id}`);
        await this.workspaceRepo.updateWorkspace(
          { enforceSso: true },
          workspace.id,
        );
      }
    } else if (process.env.OIDC_ENFORCE === 'false') {
      if (workspace.enforceSso) {
        this.logger.log(
          `Disabling SSO enforcement for workspace: ${workspace.id}`,
        );
        await this.workspaceRepo.updateWorkspace(
          { enforceSso: false },
          workspace.id,
        );
      }
    }
  }

  private async syncOidcProvider(workspace: Workspace) {
    const issuer = process.env.OIDC_ISSUER;
    const clientId = process.env.OIDC_CLIENT_ID;
    const clientSecret = process.env.OIDC_CLIENT_SECRET;

    if (!issuer || !clientId || !clientSecret) {
      return;
    }

    const existing = await this.authProviderRepo.findFirstByType(
      'oidc',
      workspace.id,
    );

    const isEnabled = process.env.OIDC_ENABLED === 'false' ? false : true;
    const allowSignup =
      process.env.OIDC_ALLOW_SIGNUP === 'false' ? false : true;
    const groupSync = process.env.OIDC_GROUP_SYNC === 'true';
    const name = process.env.OIDC_DISPLAY_NAME || 'OIDC';

    const encryptedSecret = this.encryptSecret(clientSecret);

    if (!existing) {
      this.logger.log(
        `Auto-configuring OIDC provider from environment variables for workspace: ${workspace.id}`,
      );
      await this.authProviderRepo.insertProvider({
        name,
        type: 'oidc',
        oidcIssuer: issuer,
        oidcClientId: clientId,
        oidcClientSecret: encryptedSecret,
        isEnabled,
        allowSignup,
        groupSync,
        workspaceId: workspace.id,
      });
    } else if (process.env.OIDC_OVERWRITE_ON_STARTUP === 'true') {
      this.logger.log(
        `Updating OIDC provider from environment variables for workspace: ${workspace.id}`,
      );
      await this.authProviderRepo.updateProvider(
        {
          name,
          oidcIssuer: issuer,
          oidcClientId: clientId,
          oidcClientSecret: encryptedSecret,
          isEnabled,
          allowSignup,
          groupSync,
        },
        existing.id,
        workspace.id,
      );
    }
  }

  async getProviders(workspaceId: string): Promise<AuthProvider[]> {
    let providers = await this.authProviderRepo.findByWorkspaceId(workspaceId);
    if (providers.length === 0 && process.env.OIDC_ISSUER) {
      await this.syncFromEnvironmentVariables();
      providers = await this.authProviderRepo.findByWorkspaceId(workspaceId);
    }
    return providers.map((p) => this.decryptProvider(p));
  }

  async getProviderById(
    providerId: string,
    workspaceId: string,
  ): Promise<AuthProvider> {
    const provider = await this.authProviderRepo.findById(
      providerId,
      workspaceId,
    );
    if (!provider) {
      throw new NotFoundException('SSO provider not found');
    }
    return this.decryptProvider(provider);
  }

  async createProvider(
    dto: CreateSsoProviderDto,
    workspaceId: string,
    creatorId: string,
  ): Promise<AuthProvider> {
    const newProvider = await this.authProviderRepo.insertProvider({
      name: dto.name,
      type: dto.type,
      isEnabled: false,
      allowSignup: false,
      groupSync: false,
      workspaceId,
      creatorId,
    });

    return this.decryptProvider(newProvider);
  }

  async updateProvider(
    dto: UpdateSsoProviderDto,
    workspaceId: string,
  ): Promise<AuthProvider> {
    const existing = await this.authProviderRepo.findById(
      dto.providerId,
      workspaceId,
    );
    if (!existing) {
      throw new NotFoundException('SSO provider not found');
    }

    const updateData: Partial<AuthProvider> = {};

    if (dto.name !== undefined) updateData.name = dto.name;
    if (dto.oidcIssuer !== undefined) updateData.oidcIssuer = dto.oidcIssuer;
    if (dto.oidcClientId !== undefined)
      updateData.oidcClientId = dto.oidcClientId;
    if (dto.isEnabled !== undefined) updateData.isEnabled = dto.isEnabled;
    if (dto.allowSignup !== undefined) updateData.allowSignup = dto.allowSignup;
    if (dto.groupSync !== undefined) updateData.groupSync = dto.groupSync;

    if (dto.oidcClientSecret !== undefined && dto.oidcClientSecret !== '') {
      updateData.oidcClientSecret = this.encryptSecret(dto.oidcClientSecret);
    }

    const updated = await this.authProviderRepo.updateProvider(
      updateData,
      dto.providerId,
      workspaceId,
    );

    if (!updated) {
      throw new BadRequestException('Failed to update SSO provider');
    }

    return this.decryptProvider(updated);
  }

  async deleteProvider(providerId: string, workspaceId: string): Promise<void> {
    const existing = await this.authProviderRepo.findById(
      providerId,
      workspaceId,
    );
    if (!existing) {
      throw new NotFoundException('SSO provider not found');
    }

    await this.authProviderRepo.softDeleteProvider(providerId, workspaceId);
  }

  private encryptSecret(secret: string): string {
    try {
      return this.encryptionService.encrypt(secret);
    } catch {
      return secret;
    }
  }

  public decryptSecret(secret: string | null): string | null {
    if (!secret) return null;
    try {
      return this.encryptionService.decrypt(secret);
    } catch {
      return secret;
    }
  }

  private decryptProvider(provider: AuthProvider): AuthProvider {
    return {
      ...provider,
      oidcClientSecret: this.decryptSecret(provider.oidcClientSecret),
    };
  }
}
