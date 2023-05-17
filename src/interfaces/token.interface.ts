export interface IToken {
  getId(): string;
  getRequestId(): string | undefined;
  getUserId(): string;
  getType(): string;
  getExpiresAt(): Date;
}
