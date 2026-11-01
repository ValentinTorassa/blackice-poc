import Foundation
import LocalAuthentication
import Darwin

enum HostAction: String, CaseIterable {
    case activate, enable, disable, removeConfiguration = "remove-config", deactivate
    var reason: String {
        switch self {
        case .activate: return "Blackice: activate the app filter extension"
        case .enable: return "Blackice: enable or replace app filtering policy"
        case .disable: return "Blackice: turn off app filtering"
        case .removeConfiguration: return "Blackice: remove app filtering policy"
        case .deactivate: return "Blackice: deactivate the app filter extension"
        }
    }
}

enum AuthorizationPolicy {
    case available(AppConfiguration)
    case absent
    case unreadable

    var summary: String {
        switch self {
        case .available(let config):
            let apps = config.apps.map {
                "\($0.identity.signingID)/\($0.identity.teamID ?? "unavailable") (policy sha256 \($0.policy.sha256.prefix(12)))"
            }.joined(separator: ", ")
            return "generation \(config.generation); configuration sha256 \(config.id); " +
                "unmatched \(config.unmatched); hostname mode \(config.hostnameMode); apps: \(apps)"
        case .absent: return "no saved app policy; generation/hash/apps/unmatched: none"
        case .unreadable: return "saved app policy unreadable; generation/hash/apps/unmatched: unknown"
        }
    }
}

struct AuthorizationParent {
    let pid: Int32
    let name: String

    init(pid: Int32, name: Data?) {
        self.pid = pid
        self.name = name.map { Receipt.clean($0, limit: 64) } ?? "unavailable"
    }

    static func current() -> AuthorizationParent {
        let pid = getppid()
        var buffer = [CChar](repeating: 0, count: 256)
        let length = proc_name(pid, &buffer, UInt32(buffer.count))
        let bytes = length > 0 ? Data(buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }) : nil
        return AuthorizationParent(pid: pid, name: bytes)
    }
}

struct AuthorizationPrompt {
    let action: HostAction
    let policy: AuthorizationPolicy
    let parent: AuthorizationParent

    /// One complete summary for the terminal and the authentication dialog.
    /// Parent labels are untrusted audit context, never authorization evidence.
    var reason: String {
        "\(action.reason). \(policy.summary). Parent: \(parent.name) (pid \(parent.pid), audit only)."
    }

    /// The control receipt for one user-presence result. It carries the
    /// configuration digest and generation this prompt showed, so an approval
    /// in the log can be matched to what was approved.
    func receipt(approved: Bool) -> Receipt {
        let shown: AppConfiguration?
        if case .available(let config) = policy { shown = config } else { shown = nil }
        var receipt = Receipt(scope: AppFilterConstants.controlScope, policy: shown?.id ?? "unavailable",
                              generation: shown?.generation ?? 0, point: "control", event: "owner_authentication")
        receipt.verdict = approved ? "allow" : "deny"
        receipt.reason = approved ? "user_presence_confirmed" : "user_presence_refused"
        receipt.detail = "backend=network_extension;action=\(action.rawValue);parent_pid=\(parent.pid)"
        return receipt
    }
}

/// New context per operation, no cached authorization or environment/CLI bypass.
/// Tests inject a denying authenticator into the gate, never into the host CLI.
protocol PresenceAuthenticating {
    func authenticate(reason: String, completion: @escaping (Bool) -> Void)
}

struct SystemPresenceAuthenticator: PresenceAuthenticating {
    func authenticate(reason: String, completion: @escaping (Bool) -> Void) {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedCancelTitle = "Cancel"
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            context.invalidate(); completion(false); return
        }
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
            context.invalidate()
            completion(success)
        }
    }
}

enum PresenceGate {
    static func perform(_ prompt: AuthorizationPrompt, using authenticator: PresenceAuthenticating,
                        announce: (String) -> Void,
                        denied: @escaping () -> Void, authorized: @escaping () -> Void) {
        let reason = prompt.reason
        announce(reason)
        authenticator.authenticate(reason: reason) { success in
            if success { authorized() } else { denied() }
        }
    }
}

/// The saved filter preference as the host loaded it.
struct SavedFilterState {
    let exists: Bool
    let enabled: Bool
    let configuration: Data?
}

enum HostPrecondition {
    /// Why an action would be refused. The host checks this before asking for
    /// user presence, so an approval is never spent on a request that fails
    /// anyway, and again on the state it reloads after authentication.
    static func refusal(_ action: HostAction, candidate: AppConfiguration?, saved: SavedFilterState) -> String? {
        switch action {
        case .activate:
            return nil
        case .enable:
            guard let candidate else { return "invalid_configuration" }
            guard saved.exists else { return nil }
            guard let data = saved.configuration, let current = try? AppConfiguration(data: data) else {
                return "invalid_saved_configuration"
            }
            do { try ConfigurationUpdate.validate(candidate, replacing: current) }
            catch { return "update_requires_higher_generation" }
            return nil
        case .disable:
            return saved.exists ? nil : "no_owned_configuration"
        case .removeConfiguration:
            if saved.enabled { return "disable_before_removal" }
            return saved.exists ? nil : "no_owned_configuration"
        case .deactivate:
            return saved.enabled ? "disable_before_deactivation" : nil
        }
    }
}

enum ConfigurationUpdate {
    static func validate(_ candidate: AppConfiguration, replacing current: AppConfiguration?) throws {
        if let current, candidate.generation <= current.generation {
            throw ConfigurationError.invalid("update_requires_higher_generation")
        }
    }
}

/// Activation replaces an installed extension only with this extension at the same or a higher
/// CFBundleVersion, so an older signed build cannot replace a newer one. A deliberate rollback is
/// deactivate, then activate.
enum ExtensionReplacement {
    static func allowed(existingID: String, existingVersion: String, candidateID: String, candidateVersion: String) -> Bool {
        guard existingID == AppFilterConstants.extensionBundleID, candidateID == AppFilterConstants.extensionBundleID,
              let existing = version(existingVersion), let candidate = version(candidateVersion) else { return false }
        return !candidate.lexicographicallyPrecedes(existing)
    }

    /// CFBundleVersion: one to three period-separated integers. Trailing zero components are
    /// dropped so "1" and "1.0" compare equal. Anything else is unparseable and refuses.
    static func version(_ text: String) -> [Int]? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...3).contains(parts.count) else { return nil }
        var numbers: [Int] = []
        for part in parts {
            guard !part.isEmpty, part.utf8.count <= 9, part.utf8.allSatisfy({ (48...57).contains($0) }),
                  let number = Int(part) else { return nil }
            numbers.append(number)
        }
        while numbers.last == 0 { numbers.removeLast() }
        return numbers
    }
}
