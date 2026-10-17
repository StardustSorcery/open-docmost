import { Module } from '@nestjs/common';
import { AuthProviderRepo } from './repos/auth-provider.repo';
import { AuthAccountRepo } from './repos/auth-account.repo';
import { SsoProviderService } from './services/sso-provider.service';
import { OidcAuthService } from './services/oidc-auth.service';
import { HeadlessSetupService } from './services/headless-setup.service';
import { SsoManagementController } from './controllers/sso-management.controller';
import { OidcAuthController } from './controllers/oidc-auth.controller';
import { WorkspaceModule } from '../core/workspace/workspace.module';
import { AuthModule } from '../core/auth/auth.module';

@Module({
  imports: [WorkspaceModule, AuthModule],
  controllers: [SsoManagementController, OidcAuthController],
  providers: [
    AuthProviderRepo,
    AuthAccountRepo,
    SsoProviderService,
    OidcAuthService,
    HeadlessSetupService,
  ],
  exports: [
    AuthProviderRepo,
    AuthAccountRepo,
    SsoProviderService,
    OidcAuthService,
    HeadlessSetupService,
  ],
})
export class OpenSsoModule {}
