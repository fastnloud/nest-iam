import { Inject, Injectable } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import iamConfig from '../configs/iam.config';
import { IAccessTokenJwtPayload } from '../interfaces/access-token-jwt-payload.interface';
import { IAccessToken } from '../interfaces/access-token.interface';
import { IUser } from '../interfaces/user.interface';

@Injectable()
export class AccessTokenGenerator {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(iamConfig.KEY)
    private readonly config: ConfigType<typeof iamConfig>,
  ) {}

  async generate(user: IUser): Promise<IAccessToken> {
    const ttl = this.config.jwt.accessTokenTtl;

    const expiresAt = new Date();
    expiresAt.setSeconds(expiresAt.getSeconds() + ttl);

    return {
      jwt: await this.jwtService.signAsync(
        {
          sub: user.getId(),
          username: user.getUsername(),
          roles: user.getRoles(),
        } as IAccessTokenJwtPayload,
        {
          expiresIn: this.config.jwt.accessTokenTtl,
        },
      ),
      expiresAt,
    };
  }
}
