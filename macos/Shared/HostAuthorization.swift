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

enum ConfigurationUpdate {
    static func validate(_ candidate: AppConfiguration, replacing current: AppConfiguration?) throws {
        if let current, candidate.generation <= current.generation {
            throw ConfigurationError.invalid("update_requires_higher_generation")
        }
    }
}
