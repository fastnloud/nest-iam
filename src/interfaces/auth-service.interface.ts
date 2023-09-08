import { IToken } from './token.interface';
import { IUser } from './user.interface';

export interface IAuthService {
  getValidTokenOrFail(
    id: string,
    type: string,
    requestId?: string,
  ): Promise<IToken>;
  getValidUserOrFail(username: string): Promise<IUser>;
  getUserOrFail(id: string): Promise<IUser>;
  removeToken(id: string): Promise<void>;
  saveToken(token: IToken): Promise<void>;
}
