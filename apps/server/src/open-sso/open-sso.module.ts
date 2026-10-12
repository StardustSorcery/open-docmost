import { Module } from '@nestjs/common';
import { AuthProviderRepo } from './repos/auth-provider.repo';
import { AuthAccountRepo } from './repos/auth-account.repo';
import { SsoProviderService } from './services/sso-provider.service';
import { OidcAuthService } from './services/oidc-auth.service';
import { SsoManagementController } from './controllers/sso-management.controller';
import { OidcAuthController } from './controllers/oidc-auth.controller';
import { WorkspaceModule } from '../core/workspace/workspace.module';

@Module({
  imports: [WorkspaceModule],
  controllers: [SsoManagementController, OidcAuthController],
  providers: [
    AuthProviderRepo,
    AuthAccountRepo,
    SsoProviderService,
    OidcAuthService,
  ],
  exports: [
    AuthProviderRepo,
    AuthAccountRepo,
    SsoProviderService,
    OidcAuthService,
  ],
})
export class OpenSsoModule {}
