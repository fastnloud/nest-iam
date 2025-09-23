export class LoggedOutEvent {
  constructor(
    public readonly userId: string,
    public readonly context?: Record<string, any>,
  ) {}
}
