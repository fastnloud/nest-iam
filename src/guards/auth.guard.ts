import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { IAM_AUTH_TYPE_KEY } from '../constants/iam.constants';
import { AuthType } from '../enums/auth-type.enum';
import { MODULE_OPTIONS_TOKEN } from '../iam.module-definition';
import { IModuleOptions } from '../interfaces/module-options.interface';
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
    @Inject(MODULE_OPTIONS_TOKEN)
    private readonly moduleOptions: IModuleOptions,
    private readonly reflector: Reflector,
    private readonly accessTokenGuard: AccessTokenGuard,
    private readonly noneGuard: NoneGuard,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request: Request = context.switchToHttp().getRequest();
    const authTypes = this.reflector.getAllAndOverride<AuthType[]>(
      IAM_AUTH_TYPE_KEY,
      [context.getHandler(), context.getClass()],
    ) ?? [AuthType.AccessToken];

    const guards = authTypes.map((type) => this.authTypeGuardMap[type]).flat();

    if (this.moduleOptions.publicRoutes?.length > 0) {
      const { path, method } = request;

      for (const publicRoute of this.moduleOptions.publicRoutes) {
        if (
          path.match(publicRoute.path) &&
          publicRoute.methods.includes(method)
        ) {
          return await this.noneGuard.canActivate(context);
        }
      }
    }

    for (const guard of guards) {
      if (await guard.canActivate(context)) {
        return true;
      }
    }

    throw new UnauthorizedException();
  }
}
