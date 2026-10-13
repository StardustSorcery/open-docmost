import { HeadlessSetupService } from './headless-setup.service';
import { WorkspaceRepo } from '@docmost/db/repos/workspace/workspace.repo';
import { SignupService } from '../../core/auth/services/signup.service';
import { SsoProviderService } from './sso-provider.service';

describe('HeadlessSetupService', () => {
  let service: HeadlessSetupService;
  let workspaceRepo: jest.Mocked<WorkspaceRepo>;
  let signupService: jest.Mocked<SignupService>;
  let ssoProviderService: jest.Mocked<SsoProviderService>;

  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };

    // Clean up relevant environment variables
    delete process.env.SETUP_ADMIN_EMAIL;
    delete process.env.INITIAL_ADMIN_EMAIL;
    delete process.env.ADMIN_EMAIL;
    delete process.env.SETUP_ADMIN_PASSWORD;
    delete process.env.INITIAL_ADMIN_PASSWORD;
    delete process.env.ADMIN_PASSWORD;
    delete process.env.SETUP_ADMIN_NAME;
    delete process.env.INITIAL_ADMIN_NAME;
    delete process.env.ADMIN_NAME;
    delete process.env.SETUP_WORKSPACE_NAME;
    delete process.env.INITIAL_WORKSPACE_NAME;
    delete process.env.WORKSPACE_NAME;

    workspaceRepo = {
      count: jest.fn(),
    } as any;

    signupService = {
      initialSetup: jest.fn(),
    } as any;

    ssoProviderService = {
      syncFromEnvironmentVariables: jest.fn(),
    } as any;

    service = new HeadlessSetupService(
      workspaceRepo,
      signupService,
      ssoProviderService,
    );
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('performHeadlessSetup', () => {
    it('should skip setup when workspace already exists (count > 0)', async () => {
      // Arrange
      workspaceRepo.count.mockResolvedValue(1);
      process.env.SETUP_ADMIN_EMAIL = 'admin@example.com';
      process.env.SETUP_ADMIN_PASSWORD = 'password123';

      // Act
      const result = await service.performHeadlessSetup();

      // Assert
      expect(result).toBe(false);
      expect(workspaceRepo.count).toHaveBeenCalledTimes(1);
      expect(signupService.initialSetup).not.toHaveBeenCalled();
      expect(
        ssoProviderService.syncFromEnvironmentVariables,
      ).not.toHaveBeenCalled();
    });

    it('should skip setup when workspace count is 0 but no admin email env var is set', async () => {
      // Arrange
      workspaceRepo.count.mockResolvedValue(0);

      // Act
      const result = await service.performHeadlessSetup();

      // Assert
      expect(result).toBe(false);
      expect(workspaceRepo.count).toHaveBeenCalledTimes(1);
      expect(signupService.initialSetup).not.toHaveBeenCalled();
      expect(
        ssoProviderService.syncFromEnvironmentVariables,
      ).not.toHaveBeenCalled();
    });

    it('should skip setup when admin email is invalid', async () => {
      // Arrange
      workspaceRepo.count.mockResolvedValue(0);
      process.env.SETUP_ADMIN_EMAIL = 'invalid-email';

      // Act
      const result = await service.performHeadlessSetup();

      // Assert
      expect(result).toBe(false);
      expect(workspaceRepo.count).toHaveBeenCalledTimes(1);
      expect(signupService.initialSetup).not.toHaveBeenCalled();
      expect(
        ssoProviderService.syncFromEnvironmentVariables,
      ).not.toHaveBeenCalled();
    });

    it('should successfully perform headless setup with full parameters', async () => {
      // Arrange
      workspaceRepo.count.mockResolvedValue(0);
      process.env.SETUP_ADMIN_EMAIL = 'admin@example.com';
      process.env.SETUP_ADMIN_PASSWORD = 'password123';
      process.env.SETUP_ADMIN_NAME = 'Super Admin';
      process.env.SETUP_WORKSPACE_NAME = 'Test Corp';

      signupService.initialSetup.mockResolvedValue({
        user: { id: 'user-1', email: 'admin@example.com' } as any,
        workspace: { id: 'ws-1', name: 'Test Corp' } as any,
      });

      // Act
      const result = await service.performHeadlessSetup();

      // Assert
      expect(result).toBe(true);
      expect(signupService.initialSetup).toHaveBeenCalledWith({
        name: 'Super Admin',
        email: 'admin@example.com',
        password: 'password123',
        workspaceName: 'Test Corp',
      });
      expect(
        ssoProviderService.syncFromEnvironmentVariables,
      ).toHaveBeenCalledTimes(1);
    });

    it('should successfully perform headless setup with default name, workspaceName, and auto-generated password', async () => {
      // Arrange
      workspaceRepo.count.mockResolvedValue(0);
      process.env.SETUP_ADMIN_EMAIL = 'admin@example.com';

      signupService.initialSetup.mockResolvedValue({
        user: { id: 'user-1', email: 'admin@example.com' } as any,
        workspace: { id: 'ws-1', name: 'Docmost' } as any,
      });

      // Act
      const result = await service.performHeadlessSetup();

      // Assert
      expect(result).toBe(true);
      expect(signupService.initialSetup).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'Admin',
          email: 'admin@example.com',
          workspaceName: 'Docmost',
        }),
      );

      // Verify generated password is a secure string of at least 16 characters
      const calledDto = signupService.initialSetup.mock.calls[0][0];
      expect(calledDto.password).toBeDefined();
      expect(typeof calledDto.password).toBe('string');
      expect(calledDto.password.length).toBeGreaterThanOrEqual(16);

      expect(
        ssoProviderService.syncFromEnvironmentVariables,
      ).toHaveBeenCalledTimes(1);
    });

    describe('alias environment variables', () => {
      it('should work with INITIAL_ADMIN_EMAIL, INITIAL_ADMIN_PASSWORD, INITIAL_WORKSPACE_NAME', async () => {
        // Arrange
        workspaceRepo.count.mockResolvedValue(0);
        process.env.INITIAL_ADMIN_EMAIL = 'initial-admin@example.com';
        process.env.INITIAL_ADMIN_PASSWORD = 'initpassword123';
        process.env.INITIAL_WORKSPACE_NAME = 'Initial Corp';

        signupService.initialSetup.mockResolvedValue({
          user: { id: 'user-1' } as any,
          workspace: { id: 'ws-1' } as any,
        });

        // Act
        const result = await service.performHeadlessSetup();

        // Assert
        expect(result).toBe(true);
        expect(signupService.initialSetup).toHaveBeenCalledWith({
          name: 'Admin',
          email: 'initial-admin@example.com',
          password: 'initpassword123',
          workspaceName: 'Initial Corp',
        });
        expect(
          ssoProviderService.syncFromEnvironmentVariables,
        ).toHaveBeenCalledTimes(1);
      });

      it('should work with ADMIN_EMAIL, ADMIN_PASSWORD, WORKSPACE_NAME, ADMIN_NAME', async () => {
        // Arrange
        workspaceRepo.count.mockResolvedValue(0);
        process.env.ADMIN_EMAIL = 'admin-fallback@example.com';
        process.env.ADMIN_PASSWORD = 'fallbackpassword123';
        process.env.ADMIN_NAME = 'Custom Admin Name';
        process.env.WORKSPACE_NAME = 'Fallback Workspace';

        signupService.initialSetup.mockResolvedValue({
          user: { id: 'user-1' } as any,
          workspace: { id: 'ws-1' } as any,
        });

        // Act
        const result = await service.performHeadlessSetup();

        // Assert
        expect(result).toBe(true);
        expect(signupService.initialSetup).toHaveBeenCalledWith({
          name: 'Custom Admin Name',
          email: 'admin-fallback@example.com',
          password: 'fallbackpassword123',
          workspaceName: 'Fallback Workspace',
        });
        expect(
          ssoProviderService.syncFromEnvironmentVariables,
        ).toHaveBeenCalledTimes(1);
      });
    });

    describe('error handling', () => {
      it('should catch error and return false when workspaceRepo.count throws without rethrowing', async () => {
        // Arrange
        workspaceRepo.count.mockRejectedValue(
          new Error('DB connection refused'),
        );
        process.env.SETUP_ADMIN_EMAIL = 'admin@example.com';

        // Act & Assert: should not throw
        await expect(service.performHeadlessSetup()).resolves.toBe(false);
        expect(signupService.initialSetup).not.toHaveBeenCalled();
        expect(
          ssoProviderService.syncFromEnvironmentVariables,
        ).not.toHaveBeenCalled();
      });

      it('should catch error and return false when signupService.initialSetup throws without rethrowing', async () => {
        // Arrange
        workspaceRepo.count.mockResolvedValue(0);
        process.env.SETUP_ADMIN_EMAIL = 'admin@example.com';
        process.env.SETUP_ADMIN_PASSWORD = 'password123';
        signupService.initialSetup.mockRejectedValue(
          new Error('User creation failed'),
        );

        // Act & Assert: should not throw
        await expect(service.performHeadlessSetup()).resolves.toBe(false);
        expect(signupService.initialSetup).toHaveBeenCalledTimes(1);
        expect(
          ssoProviderService.syncFromEnvironmentVariables,
        ).not.toHaveBeenCalled();
      });
    });
  });

  describe('onApplicationBootstrap', () => {
    it('should delegate to performHeadlessSetup on bootstrap', async () => {
      // Arrange
      const performHeadlessSetupSpy = jest
        .spyOn(service, 'performHeadlessSetup')
        .mockResolvedValue(true);

      // Act
      await service.onApplicationBootstrap();

      // Assert
      expect(performHeadlessSetupSpy).toHaveBeenCalledTimes(1);
    });
  });
});
