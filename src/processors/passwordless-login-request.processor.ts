import { Inject, Injectable } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { randomUUID } from 'crypto';
import { Response } from 'express';
import { CookieName } from 'src/enums/cookie-name.enum';
import iamConfig from '../configs/iam.config';
import { PasswordlessLoginTokenGenerator } from '../generators/passwordless-login-token.generator';
import { MODULE_OPTIONS_TOKEN } from '../iam.module-definition';
import { IModuleOptions } from '../interfaces/module-options.interface';
import { IUser } from '../interfaces/user.interface';

@Injectable()
export class PasswordlessLoginRequestProcessor {
  public constructor(
    private readonly passwordlessLoginTokenGenerator: PasswordlessLoginTokenGenerator,
    @Inject(MODULE_OPTIONS_TOKEN)
    private readonly moduleOptions: IModuleOptions,
    @Inject(iamConfig.KEY)
    private readonly config: ConfigType<typeof iamConfig>,
  ) {}

  public async process(user: IUser, response: Response): Promise<void> {
    const requestId = randomUUID();
    const passwordlessLoginToken =
      await this.passwordlessLoginTokenGenerator.generate(user, requestId);

    await this.moduleOptions.authService.saveTokenOrFail(
      passwordlessLoginToken,
    );

    response.cookie(CookieName.PasswordlessLoginToken, requestId, {
      secure: this.config.cookie.secure,
      sameSite: this.config.cookie.sameSite,
      expires: passwordlessLoginToken.getExpiresAt(),
      httpOnly: true,
      path: `${this.config.routePathPrefix}/auth`,
    });
  }
}
