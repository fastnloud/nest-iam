import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IAM_AUTH_TYPE_KEY } from '../constants/iam.constants';
import { AuthType } from '../enums/auth-type.enum';
import { AccessTokenGuard } from './access-token.guard';
import { NoneGuard } from './none.guard';

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly authTypeGuardMap: Record<
    AuthType,
    CanActivate | CanActivate[]
  > = {
    [AuthType.AccessToken]: this.accessTokenGuard,
    [AuthType.None]: this.noneGuard,
  };

  constructor(
    private readonly reflector: Reflector,
    private readonly accessTokenGuard: AccessTokenGuard,
    private readonly noneGuard: NoneGuard,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const authTypes = this.reflector.getAllAndOverride<AuthType[]>(
      IAM_AUTH_TYPE_KEY,
      [context.getHandler(), context.getClass()],
    ) ?? [AuthType.AccessToken];

    const guards = authTypes.map((type) => this.authTypeGuardMap[type]).flat();

    for (const guard of guards) {
      if (await Promise.resolve(guard.canActivate(context))) {
        return true;
      }
    }

    throw new UnauthorizedException();
  }
}
