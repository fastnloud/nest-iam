import { IToken } from './token.interface';
import { IUser } from './user.interface';

export interface IAuthService {
  checkToken(id: string, type: string): Promise<IToken>;
  checkUser(username: string): Promise<IUser>;
  getUser(id: string): Promise<IUser>;
  removeToken(id: string): Promise<void>;
  saveToken(userId: string, token: IToken): Promise<void>;
}
