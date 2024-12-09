export class LoggedOutEvent {
  constructor(public readonly userId: string, context?: Record<string, any>) {}
}
