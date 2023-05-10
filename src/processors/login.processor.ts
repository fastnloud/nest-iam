import { Inject, Injectable } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { randomUUID } from 'crypto';
import iamConfig from '../configs/iam.config';
import { AccessTokenGenerator } from '../generators/access-token.generator';
import { RefreshTokenGenerator } from '../generators/refresh-token.generator';
import { MODULE_OPTIONS_TOKEN } from '../iam.module-definition';
import { IModuleOptions } from '../interfaces/module-options.interface';
import { Response } from 'express';
import { IUser } from '../interfaces/user.interface';
import { TokenType } from '../enums/token-type.enum';
import { ILogin } from '../interfaces/login.interface';

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
    response: Response = null,
  ): Promise<ILogin> {
    const accessToken = await this.accessTokenGenerator.generate(user);
    const refreshToken = await this.refreshTokenGenerator.generate(
      randomUUID(),
      user,
    );

    const login = {
      accessToken: accessToken.jwt,
      refreshToken: refreshToken.jwt,
    };

    await this.moduleOptions.authService.saveToken(user.getId(), {
      id: refreshToken.id,
      type: TokenType.RefreshToken,
      expiresAt: refreshToken.expiresAt,
    });

    if (!response) {
      return login;
    }

    response.cookie(TokenType.AccessToken, accessToken.jwt, {
      secure: this.config.cookie.secure,
      httpOnly: this.config.cookie.httpOnly,
      sameSite: this.config.cookie.sameSite,
      expires: accessToken.expiresAt,
    });

    response.cookie(TokenType.RefreshToken, refreshToken.jwt, {
      secure: this.config.cookie.secure,
      httpOnly: this.config.cookie.httpOnly,
      sameSite: this.config.cookie.sameSite,
      expires: refreshToken.expiresAt,
      path: `${this.moduleOptions.routePathPrefix || ''}/auth`,
    });

    return login;
  }
}
