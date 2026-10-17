import {
  Controller,
  Get,
  Logger,
  Param,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import { FastifyReply, FastifyRequest } from 'fastify';
import { OidcAuthService } from '../services/oidc-auth.service';
import { EnvironmentService } from '../../integrations/environment/environment.service';

const OIDC_COOKIE_NAME = 'docmost_oidc_session';

@Controller('sso/oidc')
export class OidcAuthController {
  private readonly logger = new Logger(OidcAuthController.name);

  constructor(
    private readonly oidcAuthService: OidcAuthService,
    private readonly environmentService: EnvironmentService,
  ) {}

  @Get(':providerId/login')
  async login(
    @Param('providerId') providerId: string,
    @Query('redirect') redirect: string,
    @Res() res: FastifyReply,
  ) {
    try {
      const { authUrl, sessionCookie } =
        await this.oidcAuthService.initiateLogin(providerId, redirect);

      res.setCookie(OIDC_COOKIE_NAME, sessionCookie, {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        maxAge: 600,
        secure: this.environmentService.isHttps(),
      });

      return res.status(302).redirect(authUrl);
    } catch (err: any) {
      this.logger.error(`OIDC login error: ${err.message}`, err.stack);
      return res
        .status(302)
        .redirect(`/login?error=${encodeURIComponent(err.message || 'Login initialization failed')}`);
    }
  }

  @Get('callback')
  async staticCallback(
    @Query() query: { code?: string; state?: string; error?: string; error_description?: string },
    @Req() req: FastifyRequest,
    @Res() res: FastifyReply,
  ) {
    return this.callback(undefined as any, query, req, res);
  }

  @Get(':providerId/callback')
  async callback(
    @Param('providerId') providerId: string | undefined,
    @Query() query: { code?: string; state?: string; error?: string; error_description?: string },
    @Req() req: FastifyRequest,
    @Res() res: FastifyReply,
  ) {
    try {
      const cookies = (req.cookies || {}) as Record<string, string>;
      const sessionCookie = cookies[OIDC_COOKIE_NAME];

      res.clearCookie(OIDC_COOKIE_NAME, {
        path: '/',
      });

      const requestUrl = req.raw.url;
      const { authToken, redirectUrl } =
        await this.oidcAuthService.handleCallback(
          providerId,
          query,
          sessionCookie,
          requestUrl,
        );

      res.setCookie('authToken', authToken, {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        expires: this.environmentService.getCookieExpiresIn(),
        secure: this.environmentService.isHttps(),
      });

      return res.status(302).redirect(redirectUrl);
    } catch (err: any) {
      this.logger.error(`OIDC callback error: ${err.message}`, err.stack);
      return res
        .status(302)
        .redirect(`/login?error=${encodeURIComponent(err.message || 'Authentication failed')}`);
    }
  }
}
