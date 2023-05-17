import { Inject, Injectable } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import iamConfig from '../configs/iam.config';
import { MODULE_OPTIONS_TOKEN } from '../iam.module-definition';
import { IModuleOptions } from '../interfaces/module-options.interface';
import { Response } from 'express';
import { IUser } from '../interfaces/user.interface';
import { TokenType } from '../enums/token-type.enum';
import { PasswordlessLoginTokenGenerator } from '../generators/passwordless-login-token.generator';
import { randomUUID } from 'crypto';

@Injectable()
export class PasswordlessLoginRequestProcessor {
  public constructor(
    private readonly passwordlessLoginTokenGenerator: PasswordlessLoginTokenGenerator,
    @Inject(MODULE_OPTIONS_TOKEN)
    private readonly moduleOptions: IModuleOptions,
    @Inject(iamConfig.KEY)
    private readonly config: ConfigType<typeof iamConfig>,
  ) {}

  public async process(user: IUser, response?: Response): Promise<void> {
    const requestId = randomUUID();
    const passwordlessLoginToken =
      await this.passwordlessLoginTokenGenerator.generate(user, requestId);

    await this.moduleOptions.authService.saveToken(passwordlessLoginToken);

    if (!response) {
      return;
    }

    response.cookie(TokenType.PasswordlessLoginToken, requestId, {
      secure: this.config.cookie.secure,
      httpOnly: this.config.cookie.httpOnly,
      sameSite: this.config.cookie.sameSite,
      expires: passwordlessLoginToken.getExpiresAt(),
      path: `${this.moduleOptions.routePathPrefix || ''}/auth`,
    });
  }
}
