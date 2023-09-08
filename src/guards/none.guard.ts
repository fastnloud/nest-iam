import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { CookieName } from 'src/enums/cookie-name.enum';
import { IAM_REQUEST_USER_KEY } from '../constants/iam.constants';
import { IAccessTokenJwtPayload } from '../interfaces/access-token-jwt-payload.interface';
import { IActiveUser } from '../interfaces/active-user.interface';

@Injectable()
export class NoneGuard implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const accessToken: string | undefined =
      request.cookies[CookieName.AccessToken];

    try {
      const accessTokenJwtPayload: IAccessTokenJwtPayload =
        await this.jwtService.verifyAsync(accessToken);

      const activeUser: IActiveUser = {
        userId: accessTokenJwtPayload.sub,
        roles: accessTokenJwtPayload.roles,
      };

      request[IAM_REQUEST_USER_KEY] = activeUser;
    } catch {
      return true;
    }

    return true;
  }
}
