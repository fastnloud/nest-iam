import { IToken } from '../interfaces/token.interface';

export class TokenModel implements IToken {
  constructor(
    public readonly id: string,
    public readonly type: string,
    public readonly userId: string,
    public readonly expiresAt: Date,
    public readonly requestId?: string,
  ) {}

  public getId(): string {
    return this.id;
  }

  public getRequestId(): string | undefined {
    return this.requestId;
  }

  public getUserId(): string {
    return this.userId;
  }

  public getType(): string {
    return this.type;
  }

  public getExpiresAt(): Date {
    return this.expiresAt;
  }
}
