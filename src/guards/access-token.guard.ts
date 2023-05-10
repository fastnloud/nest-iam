import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { IAM_REQUEST_USER_KEY } from '../constants/iam.constants';
import { TokenType } from '../enums/token-type.enum';
import { IAccessTokenJwtPayload } from '../interfaces/access-token-jwt-payload.interface';
import { IActiveUser } from '../interfaces/active-user.interface';

@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();

    try {
      const accessTokenJwtPayload: IAccessTokenJwtPayload =
        await this.jwtService.verifyAsync(
          request.cookies[TokenType.AccessToken] ?? '',
        );

      const activeUser: IActiveUser = {
        userId: accessTokenJwtPayload.sub,
        roles: accessTokenJwtPayload.roles,
      };

      request[IAM_REQUEST_USER_KEY] = activeUser;
    } catch {
      throw new UnauthorizedException();
    }

    return true;
  }
}
