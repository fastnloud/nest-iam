export interface IRefreshTokenJwtPayload {
  id: string;
  sub: string;
  username: string;
  roles: string[];
}
