export class LoggedInEvent {
  constructor(
    public readonly userId: string,
    public readonly context?: Record<string, any>,
  ) {}
}
