import { IToken } from './token.interface';
import { IUser } from './user.interface';

export interface IAuthService {
  findOneUserOrFail(id: string): Promise<IUser>;
  findOneValidTokenOrFail(
    id: string,
    type: string,
    requestId?: string,
  ): Promise<IToken>;
  findOneValidUserOrFail(username: string): Promise<IUser>;
  removeTokenOrFail(id: string): Promise<void>;
  saveTokenOrFail(token: IToken, context?: Record<string, any>): Promise<void>;
}
