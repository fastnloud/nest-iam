import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { IAM_REQUEST_USER_KEY } from '../constants/iam.constants';
import { IActiveUser } from '../interfaces/active-user.interface';

export const ActiveUser = createParamDecorator(
  (field: keyof IActiveUser | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user: IActiveUser | undefined = request[IAM_REQUEST_USER_KEY];

    return field ? user?.[field] : user;
  },
);
