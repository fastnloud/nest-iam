import { IAuthService } from './auth-service.interface';
import { IPublicRoute } from './public-route.interface';

export interface IModuleOptions {
  authService: IAuthService;
  publicRoutes?: IPublicRoute[];
  passwordlessLoginOptions?: {
    throwNotFoundError?: boolean;
  };
}
