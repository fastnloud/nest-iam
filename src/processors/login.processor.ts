import { Inject, Injectable } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { Request, Response } from 'express';
import iamConfig from '../configs/iam.config';
import { CookieName } from '../enums/cookie-name.enum';
import { TokenType } from '../enums/token-type.enum';
import { AccessTokenGenerator } from '../generators/access-token.generator';
import { RefreshTokenGenerator } from '../generators/refresh-token.generator';
import { MODULE_OPTIONS_TOKEN } from '../iam.module-definition';
import { ILogin } from '../interfaces/login.interface';
import { IModuleOptions } from '../interfaces/module-options.interface';
import { IUser } from '../interfaces/user.interface';
import { TokenModel } from '../models/token.model';

@Injectable()
export class LoginProcessor {
  public constructor(
    private readonly accessTokenGenerator: AccessTokenGenerator,
    private readonly refreshTokenGenerator: RefreshTokenGenerator,
    @Inject(MODULE_OPTIONS_TOKEN)
    private readonly moduleOptions: IModuleOptions,
    @Inject(iamConfig.KEY)
    private readonly config: ConfigType<typeof iamConfig>,
  ) {}

  public async process(
    user: IUser,
    request: Request,
    response: Response,
  ): Promise<ILogin> {
    const accessToken = await this.accessTokenGenerator.generate(user);
    const refreshToken = await this.refreshTokenGenerator.generate(user);

    const login = {
      accessToken: accessToken.jwt,
      refreshToken: refreshToken.jwt,
    };

    await this.moduleOptions.authService.saveTokenOrFail(
      new TokenModel(
        refreshToken.id,
        TokenType.RefreshToken,
        user.getId(),
        refreshToken.expiresAt,
      ),
      { request },
    );

    response.cookie(CookieName.AccessToken, accessToken.jwt, {
      secure: this.config.cookie.secure,
      sameSite: this.config.cookie.sameSite,
      expires: accessToken.expiresAt,
      httpOnly: true,
    });

    response.cookie(CookieName.RefreshToken, refreshToken.jwt, {
      secure: this.config.cookie.secure,
      sameSite: this.config.cookie.sameSite,
      expires: refreshToken.expiresAt,
      httpOnly: true,
      path: `${this.config.routePathPrefix}/auth`,
    });

    response.cookie(
      CookieName.ActiveUser,
      JSON.stringify({
        id: user.getId(),
        email: user.getUsername(),
        roles: user.getRoles(),
      }),
      {
        secure: this.config.cookie.secure,
        sameSite: this.config.cookie.sameSite,
        expires: refreshToken.expiresAt,
      },
    );

    return login;
  }
}
