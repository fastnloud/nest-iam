import { IToken } from './token.interface';
import { IUser } from './user.interface';

export interface IAuthService {
  findOneUserOrFail(id: string, context?: Record<string, any>): Promise<IUser>;
  findOneValidTokenOrFail(
    id: string,
    type: string,
    context?: Record<string, any>,
  ): Promise<IToken>;
  findOneValidUserOrFail(
    username: string,
    context?: Record<string, any>,
  ): Promise<IUser>;
  removeTokenOrFail(id: string, context?: Record<string, any>): Promise<void>;
  saveTokenOrFail(token: IToken, context?: Record<string, any>): Promise<void>;
}
