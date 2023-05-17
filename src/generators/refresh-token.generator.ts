import { Inject, Injectable } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import iamConfig from '../configs/iam.config';
import { IRefreshTokenJwtPayload } from '../interfaces/refresh-token-jwt-payload.interface';
import { IRefreshToken } from '../interfaces/refresh-token.interface';
import { IUser } from '../interfaces/user.interface';
import { randomUUID } from 'crypto';

@Injectable()
export class RefreshTokenGenerator {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(iamConfig.KEY)
    private readonly config: ConfigType<typeof iamConfig>,
  ) {}

  async generate(user: IUser): Promise<IRefreshToken> {
    const id = randomUUID();
    const ttl = this.config.jwt.refreshTokenTtl;

    const expiresAt = new Date();
    expiresAt.setSeconds(expiresAt.getSeconds() + ttl);

    return {
      id,
      jwt: await this.jwtService.signAsync(
        {
          id,
          sub: user.getId(),
          username: user.getUsername(),
          roles: user.getRoles(),
        } as IRefreshTokenJwtPayload,
        {
          expiresIn: this.config.jwt.refreshTokenTtl,
        },
      ),
      expiresAt,
    };
  }
}
