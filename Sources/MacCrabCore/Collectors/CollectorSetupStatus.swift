/// A lifecycle transition after a collector has checked its setup. Receiving
/// an unrelated event is deliberately not a recovery signal.
public enum CollectorSetupStatus: Sendable, Equatable {
    case configured
    case unavailable(reason: String)
}
