import {
  Injectable,
  Logger,
  OnApplicationBootstrap,
  Optional,
} from '@nestjs/common';
import * as crypto from 'crypto';
import { WorkspaceRepo } from '@docmost/db/repos/workspace/workspace.repo';
import { SignupService } from '../../core/auth/services/signup.service';
import { SsoProviderService } from './sso-provider.service';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

@Injectable()
export class HeadlessSetupService implements OnApplicationBootstrap {
  private readonly logger = new Logger(HeadlessSetupService.name);

  constructor(
    private readonly workspaceRepo: WorkspaceRepo,
    private readonly signupService: SignupService,
    @Optional() private readonly ssoProviderService?: SsoProviderService,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    await this.performHeadlessSetup();
  }

  async performHeadlessSetup(): Promise<boolean> {
    try {
      const workspaceCount = await this.workspaceRepo.count();
      if (workspaceCount > 0) {
        return false;
      }

      const adminEmail =
        process.env.SETUP_ADMIN_EMAIL ||
        process.env.INITIAL_ADMIN_EMAIL ||
        process.env.ADMIN_EMAIL;

      if (!adminEmail) {
        return false;
      }

      if (!EMAIL_REGEX.test(adminEmail)) {
        this.logger.warn(
          `Invalid admin email provided for headless setup: "${adminEmail}"`,
        );
        return false;
      }

      const isRandomPassword =
        !process.env.SETUP_ADMIN_PASSWORD &&
        !process.env.INITIAL_ADMIN_PASSWORD &&
        !process.env.ADMIN_PASSWORD;

      const adminPassword =
        process.env.SETUP_ADMIN_PASSWORD ||
        process.env.INITIAL_ADMIN_PASSWORD ||
        process.env.ADMIN_PASSWORD ||
        crypto.randomBytes(32).toString('hex');

      if (isRandomPassword) {
        this.logger.log(
          'No initial admin password specified. Generated a random secure password for local login; authenticate via OIDC.',
        );
      }

      const adminName =
        process.env.SETUP_ADMIN_NAME ||
        process.env.INITIAL_ADMIN_NAME ||
        process.env.ADMIN_NAME ||
        'Admin';

      const workspaceName =
        process.env.SETUP_WORKSPACE_NAME ||
        process.env.INITIAL_WORKSPACE_NAME ||
        process.env.WORKSPACE_NAME ||
        'Docmost';

      const result = await this.signupService.initialSetup({
        name: adminName,
        email: adminEmail,
        password: adminPassword,
        workspaceName,
      });

      this.logger.log(
        `Headless setup completed successfully. Workspace: "${result?.workspace?.name ?? workspaceName}", Admin: "${result?.user?.email ?? adminEmail}"`,
      );

      if (this.ssoProviderService) {
        await this.ssoProviderService.syncFromEnvironmentVariables();
      }

      return true;
    } catch (error) {
      this.logger.error('Failed to perform headless setup', error);
      return false;
    }
  }
}
