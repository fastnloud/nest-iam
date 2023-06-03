import { Inject, Injectable } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { randomUUID } from 'crypto';
import iamConfig from '../configs/iam.config';
import { TokenType } from '../enums/token-type.enum';
import { IToken } from '../interfaces/token.interface';
import { IUser } from '../interfaces/user.interface';
import { TokenModel } from '../models/token.model';

@Injectable()
export class PasswordlessLoginTokenGenerator {
  constructor(
    @Inject(iamConfig.KEY)
    private readonly config: ConfigType<typeof iamConfig>,
  ) {}

  async generate(user: IUser, requestId: string): Promise<IToken> {
    const id = randomUUID();
    const ttl = this.config.auth.passwordless.tokenTtl;

    const expiresAt = new Date();
    expiresAt.setSeconds(expiresAt.getSeconds() + ttl);

    return new TokenModel(
      id,
      TokenType.PasswordlessLoginToken,
      user.getId(),
      expiresAt,
      requestId,
    );
  }
}
