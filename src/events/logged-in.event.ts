export class LoggedInEvent {
  constructor(
    public readonly userId: string,
    context?: Record<string, any>,
  ) {}
}
