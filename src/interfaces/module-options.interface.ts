import { IAuthService } from './auth-service.interface';

export interface IModuleOptions {
  authService: IAuthService;
  routePathPrefix?: string;
}
