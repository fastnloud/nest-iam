import { IToken } from './token.interface';
import { IUser } from './user.interface';

export interface IAuthService {
  checkToken(id: string, type: string): Promise<IToken>;
  checkUser(username: string): Promise<IUser>;
  getUser(id: string): Promise<IUser>;
  logout(userId: string): Promise<void>;
  removeToken(id: string): Promise<void>;
  saveToken(userId: string, token: IToken): Promise<void>;
}
