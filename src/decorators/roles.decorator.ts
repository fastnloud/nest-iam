import { SetMetadata } from '@nestjs/common';
import { IAM_ROLES_KEY } from '../constants/iam.constants';

export const Roles = (...roles: string[]) => SetMetadata(IAM_ROLES_KEY, roles);
