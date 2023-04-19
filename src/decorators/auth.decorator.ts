import { SetMetadata } from '@nestjs/common';
import { IAM_AUTH_TYPE_KEY } from '../constants/iam.constants';
import { AuthType } from '../enums/auth-type.enum';

export const Auth = (...authTypes: AuthType[]) =>
  SetMetadata(IAM_AUTH_TYPE_KEY, authTypes);
