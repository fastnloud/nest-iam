import { Inject, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';
import { IRefreshTokenJwtPayload } from 'src/interfaces/refresh-token-jwt-payload.interface';
import { TokenType } from '../enums/token-type.enum';
import { MODULE_OPTIONS_TOKEN } from '../iam.module-definition';
import { IModuleOptions } from '../interfaces/module-options.interface';

@Injectable()
export class LogoutProcessor {
  public constructor(
    private readonly jwtService: JwtService,
    @Inject(MODULE_OPTIONS_TOKEN)
    private readonly moduleOptions: IModuleOptions,
  ) {}

  public async process(request: Request, response: Response): Promise<void> {
    try {
      const refreshTokenJwtPayload: IRefreshTokenJwtPayload =
        await this.jwtService.verifyAsync(
          request.cookies[TokenType.RefreshToken],
        );

      await this.moduleOptions.authService.removeToken(
        refreshTokenJwtPayload.id,
      );
    } catch {}

    response.clearCookie(TokenType.AccessToken);
    response.clearCookie(TokenType.RefreshToken, {
      path: `${this.moduleOptions.routePathPrefix || ''}/auth`,
    });
  }
}
