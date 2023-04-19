export interface IUser {
  getId(): string;
  getUsername(): string;
  getPassword(): string;
  getRoles(): string[];
}
