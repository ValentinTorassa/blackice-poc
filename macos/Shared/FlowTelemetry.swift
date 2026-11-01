import Foundation

struct OutsideScopeCounts: Equatable {
    var allowed: UInt64 = 0
    var denied: UInt64 = 0
    var isEmpty: Bool { allowed == 0 && denied == 0 }
}

/// No identity, destination, port or hostname is retained for unbound traffic.
final class FlowTelemetry {
    private let lock = NSLock()
    private var counts = OutsideScopeCounts()

    /// True only when a per-flow diagnostic is appropriate (bound app or error).
    func shouldLog(_ result: AppDecision) -> Bool {
        guard result.scope == "app-unbound", result.decision.reason.hasPrefix("outside_scope") else { return true }
        lock.lock(); defer { lock.unlock() }
        if result.decision.allowed { counts.allowed = counts.allowed == .max ? .max : counts.allowed + 1 }
        else { counts.denied = counts.denied == .max ? .max : counts.denied + 1 }
        return false
    }

    func drain() -> OutsideScopeCounts {
        lock.lock(); defer { lock.unlock() }
        let previous = counts; counts = OutsideScopeCounts()
        return previous
    }
}
