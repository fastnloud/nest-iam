import { Inject, Injectable } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { randomUUID } from 'crypto';
import { Request } from 'express';
import iamConfig from '../configs/iam.config';
import { IRefreshTokenJwtPayload } from '../interfaces/refresh-token-jwt-payload.interface';
import { IRefreshToken } from '../interfaces/refresh-token.interface';
import { IUser } from '../interfaces/user.interface';

@Injectable()
export class RefreshTokenGenerator {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(iamConfig.KEY)
    private readonly config: ConfigType<typeof iamConfig>,
  ) {}

  async generate(user: IUser, request: Request): Promise<IRefreshToken> {
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
          audience: request.hostname,
          issuer: request.hostname,
          expiresIn: this.config.jwt.refreshTokenTtl,
        },
      ),
      expiresAt,
    };
  }
}
