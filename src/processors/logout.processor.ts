import { Inject, Injectable } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';
import iamConfig from '../configs/iam.config';
import { CookieName } from '../enums/cookie-name.enum';
import { MODULE_OPTIONS_TOKEN } from '../iam.module-definition';
import { IModuleOptions } from '../interfaces/module-options.interface';
import { IRefreshTokenJwtPayload } from '../interfaces/refresh-token-jwt-payload.interface';

@Injectable()
export class LogoutProcessor {
  public constructor(
    private readonly jwtService: JwtService,
    @Inject(MODULE_OPTIONS_TOKEN)
    private readonly moduleOptions: IModuleOptions,
    @Inject(iamConfig.KEY)
    private readonly config: ConfigType<typeof iamConfig>,
  ) {}

  public async process(request: Request, response: Response): Promise<void> {
    try {
      const refreshTokenJwtPayload: IRefreshTokenJwtPayload =
        await this.jwtService.verifyAsync(
          request.cookies[CookieName.RefreshToken],
        );

      await this.moduleOptions.authService.removeTokenOrFail(
        refreshTokenJwtPayload.id,
        { request },
      );
    } catch {}

    response.clearCookie(CookieName.AccessToken);
    response.clearCookie(CookieName.RefreshToken, {
      path: `${this.moduleOptions?.routePathPrefix ?? ''}/auth`,
    });
    response.clearCookie(CookieName.ActiveUser);
  }
}
