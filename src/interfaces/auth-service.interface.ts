import { IToken } from './token.interface';
import { IUser } from './user.interface';

export interface IAuthService {
  checkToken(id: string, type: string, requestId?: string): Promise<IToken>;
  checkUser(username: string): Promise<IUser>;
  getUser(id: string): Promise<IUser>;
  removeToken(id: string): Promise<void>;
  saveToken(token: IToken): Promise<void>;
}
