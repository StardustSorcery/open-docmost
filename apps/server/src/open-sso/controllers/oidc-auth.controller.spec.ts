import { OidcAuthController } from './oidc-auth.controller';
import { OidcAuthService } from '../services/oidc-auth.service';
import { EnvironmentService } from '../../integrations/environment/environment.service';

describe('OidcAuthController', () => {
  let controller: OidcAuthController;
  let oidcAuthService: jest.Mocked<OidcAuthService>;
  let environmentService: jest.Mocked<EnvironmentService>;

  beforeEach(() => {
    oidcAuthService = {
      initiateLogin: jest.fn(),
      handleCallback: jest.fn(),
    } as any;

    environmentService = {
      isHttps: jest.fn().mockReturnValue(false),
      getCookieExpiresIn: jest.fn().mockReturnValue(new Date(Date.now() + 3600000)),
    } as any;

    controller = new OidcAuthController(oidcAuthService, environmentService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('login', () => {
    it('should set session cookie and redirect to authUrl', async () => {
      oidcAuthService.initiateLogin.mockResolvedValue({
        authUrl: 'https://idp.example.com/auth',
        sessionCookie: 'enc-cookie-data',
      });

      const mockRes: any = {
        setCookie: jest.fn(),
        status: jest.fn().mockReturnThis(),
        redirect: jest.fn(),
      };

      await controller.login('p1', '/redirect', mockRes);

      expect(mockRes.setCookie).toHaveBeenCalledWith(
        'docmost_oidc_session',
        'enc-cookie-data',
        expect.objectContaining({ httpOnly: true }),
      );
      expect(mockRes.status).toHaveBeenCalledWith(302);
      expect(mockRes.redirect).toHaveBeenCalledWith('https://idp.example.com/auth');
    });
  });

  describe('callback', () => {
    it('should exchange code for authToken, clear session cookie, set authToken, and redirect', async () => {
      oidcAuthService.handleCallback.mockResolvedValue({
        authToken: 'jwt-auth-token',
        redirectUrl: '/dashboard',
      });

      const mockReq: any = {
        cookies: {
          docmost_oidc_session: 'enc-cookie-data',
        },
        raw: {
          url: '/api/sso/oidc/p1/callback?code=123&state=abc',
        },
      };

      const mockRes: any = {
        clearCookie: jest.fn(),
        setCookie: jest.fn(),
        status: jest.fn().mockReturnThis(),
        redirect: jest.fn(),
      };

      await controller.callback(
        'p1',
        { code: '123', state: 'abc' },
        mockReq,
        mockRes,
      );

      expect(mockRes.clearCookie).toHaveBeenCalledWith('docmost_oidc_session', { path: '/' });
      expect(mockRes.setCookie).toHaveBeenCalledWith(
        'authToken',
        'jwt-auth-token',
        expect.objectContaining({ httpOnly: true }),
      );
      expect(mockRes.status).toHaveBeenCalledWith(302);
      expect(mockRes.redirect).toHaveBeenCalledWith('/dashboard');
    });

    it('should support staticCallback without explicit providerId', async () => {
      oidcAuthService.handleCallback.mockResolvedValue({
        authToken: 'jwt-auth-token',
        redirectUrl: '/dashboard',
      });

      const mockReq: any = {
        cookies: {
          docmost_oidc_session: 'enc-cookie-data',
        },
        raw: {
          url: '/api/sso/oidc/callback?code=123&state=abc',
        },
      };

      const mockRes: any = {
        clearCookie: jest.fn(),
        setCookie: jest.fn(),
        status: jest.fn().mockReturnThis(),
        redirect: jest.fn(),
      };

      await controller.staticCallback(
        { code: '123', state: 'abc' },
        mockReq,
        mockRes,
      );

      expect(oidcAuthService.handleCallback).toHaveBeenCalledWith(
        undefined,
        { code: '123', state: 'abc' },
        'enc-cookie-data',
        '/api/sso/oidc/callback?code=123&state=abc',
      );
      expect(mockRes.status).toHaveBeenCalledWith(302);
      expect(mockRes.redirect).toHaveBeenCalledWith('/dashboard');
    });
  });
});
