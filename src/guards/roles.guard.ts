import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import {
  IAM_REQUEST_USER_KEY,
  IAM_ROLES_KEY,
} from '../constants/iam.constants';
import { IActiveUser } from '../interfaces/active-user.interface';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const roles = this.reflector.getAllAndOverride<string[]>(IAM_ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!roles) {
      return true;
    }

    const user: IActiveUser | undefined = context.switchToHttp().getRequest()[
      IAM_REQUEST_USER_KEY
    ];

    return roles.some((role) => user && user.roles.includes(role));
  }
}
