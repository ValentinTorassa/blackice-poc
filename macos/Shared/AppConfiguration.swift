import Foundation

enum AppFilterConstants {
    static let hostBundleID = "com.valentorassa.blackice"
    static let extensionBundleID = "com.valentorassa.blackice.filter"
    static let configurationKey = "blackice.appscope.configuration"
    static let logSubsystem = "com.valentorassa.blackice.filter"
}

struct AppBindingDocument: Codable {
    let scope: String
    let teamID: String
    let signingID: String
    /// Exact UTF-8 policy bytes. No reserialization before computing the policy ID.
    let policyJSON: String
    let policySHA256: String
    enum CodingKeys: String, CodingKey {
        case scope, teamID = "team_id", signingID = "signing_id", policyJSON = "policy_json"
        case policySHA256 = "policy_sha256"
    }
    init(scope: String, teamID: String, signingID: String, policyJSON: String) {
        self.scope = scope; self.teamID = teamID; self.signingID = signingID; self.policyJSON = policyJSON
        policySHA256 = digestHex(Data(policyJSON.utf8))
    }
    init(from decoder: Decoder) throws {
        try decoder.rejectUnknownKeys(["scope", "team_id", "signing_id", "policy_json", "policy_sha256"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        scope = try c.decode(String.self, forKey: .scope)
        teamID = try c.decode(String.self, forKey: .teamID)
        signingID = try c.decode(String.self, forKey: .signingID)
        policyJSON = try c.decode(String.self, forKey: .policyJSON)
        policySHA256 = try c.decode(String.self, forKey: .policySHA256)
    }
}

struct AppConfigurationDocument: Codable {
    let version: String
    let generation: UInt32
    let unmatched: String
    let hostnameMode: String
    let apps: [AppBindingDocument]
    enum CodingKeys: String, CodingKey { case version, generation, unmatched, hostnameMode = "hostname_mode", apps }
    init(generation: UInt32, unmatched: String, hostnameMode: String, apps: [AppBindingDocument]) {
        version = "blackice.appscope/v0"
        self.generation = generation; self.unmatched = unmatched; self.hostnameMode = hostnameMode; self.apps = apps
    }
    init(from decoder: Decoder) throws {
        try decoder.rejectUnknownKeys(["version", "generation", "unmatched", "hostname_mode", "apps"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(String.self, forKey: .version)
        generation = try c.decode(UInt32.self, forKey: .generation)
        unmatched = try c.decode(String.self, forKey: .unmatched)
        hostnameMode = try c.decode(String.self, forKey: .hostnameMode)
        apps = try c.decode([AppBindingDocument].self, forKey: .apps)
    }
}

func validSigningID(_ text: String) -> Bool {
    !text.isEmpty && text.utf8.count <= 255 && text.utf8.allSatisfy {
        (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || [45, 46, 95].contains($0)
    }
}

func validTeamID(_ text: String) -> Bool {
    text.utf8.count == 10 && text.utf8.allSatisfy { (65...90).contains($0) || (48...57).contains($0) }
}

struct SigningIdentity: Equatable {
    let signingID: String
    let teamID: String?
    var label: String { (teamID ?? "apple") + "/" + signingID }
}

enum IdentityResolution: Equatable {
    case verified(SigningIdentity)
    case adHoc
    case unresolved
    case invalidSignature

    var verifiedIdentity: SigningIdentity? {
        if case .verified(let identity) = self { return identity }
        return nil
    }
    var label: String {
        switch self {
        case .verified(let identity): return identity.label
        case .adHoc: return "adhoc"
        case .unresolved: return "unknown"
        case .invalidSignature: return "invalid_signature"
        }
    }
}

struct AppBinding {
    let scope: String
    let identity: SigningIdentity
    let policy: NetworkPolicy
}

struct AppConfiguration {
    let id: String
    let generation: UInt32
    let unmatched: String
    let hostnameMode: String
    let apps: [AppBinding]

    init(data: Data) throws {
        let raw = try StrictJSON.decode(AppConfigurationDocument.self, from: data)
        guard raw.version == "blackice.appscope/v0", raw.generation > 0,
              ["allow", "deny"].contains(raw.unmatched),
              ["ip-only", "os-metadata"].contains(raw.hostnameMode),
              !raw.apps.isEmpty, raw.apps.count <= 256 else {
            throw ConfigurationError.invalid("invalid_app_configuration")
        }
        var scopes = Set<String>(), identities = Set<String>()
        apps = try raw.apps.map { app in
            guard validTeamID(app.teamID), validSigningID(app.signingID),
                  app.scope.hasPrefix("app-"), app.scope.utf8.count <= 64, validSigningID(app.scope),
                  scopes.insert(app.scope).inserted,
                  identities.insert(app.teamID + "/" + app.signingID).inserted else {
                throw ConfigurationError.invalid("invalid_or_duplicate_app_binding")
            }
            let policy = try NetworkPolicy(data: Data(app.policyJSON.utf8))
            guard app.policySHA256 == policy.sha256 else {
                throw ConfigurationError.invalid("policy_sha256_mismatch")
            }
            guard raw.hostnameMode == "os-metadata" || policy.patterns.isEmpty else {
                throw ConfigurationError.invalid("unsupported_capability_hostname")
            }
            return AppBinding(scope: app.scope,
                              identity: SigningIdentity(signingID: app.signingID, teamID: app.teamID), policy: policy)
        }
        id = digestID(data); generation = raw.generation; unmatched = raw.unmatched; hostnameMode = raw.hostnameMode
    }
}

/// Immutable snapshots; no file reads or mutable policy references in a callback.
final class SnapshotStore {
    private let lock = NSLock()
    private var current: AppConfiguration?

    func read() -> AppConfiguration? {
        lock.lock(); defer { lock.unlock() }
        return current
    }

    func install(_ candidate: AppConfiguration) throws {
        lock.lock(); defer { lock.unlock() }
        if let current {
            if candidate.generation == current.generation && candidate.id == current.id { return }
            guard candidate.generation > current.generation else {
                throw ConfigurationError.invalid("stale_generation")
            }
        }
        current = candidate
    }

    func clear() {
        lock.lock(); defer { lock.unlock() }
        current = nil
    }
}

struct FlowFacts {
    enum Direction { case inbound, outbound, unknown }
    let direction: Direction
    let app: IdentityResolution
    let process: IdentityResolution
    let supportedSocket: Bool
    let isTCP: Bool
    let hostname: String?
    let ip: IPAddress?
    let port: UInt16?
}

struct AppDecision {
    let scope: String
    let policy: String
    let generation: UInt32
    let decision: Decision
    var requiredTLSHost: String? = nil
    var echPresent = false
}

enum AppEvaluator {
    static func evaluate(_ flow: FlowFacts, configuration: AppConfiguration?) -> AppDecision {
        guard let config = configuration else {
            return AppDecision(scope: "app-unavailable", policy: "unavailable", generation: 0,
                               decision: Decision(allowed: false, reason: "configuration_unavailable"))
        }
        func unbound(_ decision: Decision) -> AppDecision {
            AppDecision(scope: "app-unbound", policy: config.id, generation: config.generation, decision: decision)
        }
        guard flow.direction != .unknown else {
            return unbound(Decision(allowed: false, reason: "unknown_direction"))
        }
        // Only a positively identified ad hoc guest can use unmatched. Failed
        // resolution or signed-code validation must never fall into this path.
        if flow.app == .adHoc {
            return unbound(Decision(allowed: config.unmatched == "allow", reason: "outside_scope_adhoc"))
        }
        guard let app = flow.app.verifiedIdentity else {
            return unbound(Decision(allowed: false, reason: "unknown_app_identity"))
        }
        guard let binding = config.apps.first(where: { $0.identity == app }) else {
            return unbound(Decision(allowed: config.unmatched == "allow",
                                   reason: flow.direction == .inbound ? "outside_scope_inbound" : "outside_scope"))
        }
        let decision: Decision
        if flow.direction == .inbound {
            decision = Decision(allowed: false, reason: "inbound_not_allowed")
        } else if !flow.supportedSocket {
            decision = Decision(allowed: false, reason: "unsupported_socket")
        } else {
            decision = binding.policy.evaluate(hostname: config.hostnameMode == "os-metadata" ? flow.hostname : nil,
                                               ip: flow.ip, port: flow.port)
        }
        if decision.allowed && decision.reason == "allowed_by_rule" {
            guard flow.isTCP, let host = flow.hostname.flatMap(normalizeHost) else {
                return AppDecision(scope: binding.scope, policy: binding.policy.id, generation: config.generation,
                                   decision: Decision(allowed: false, reason: "domain_requires_tls_tcp"))
            }
            return AppDecision(scope: binding.scope, policy: binding.policy.id, generation: config.generation,
                               decision: decision, requiredTLSHost: host)
        }
        return AppDecision(scope: binding.scope, policy: binding.policy.id, generation: config.generation, decision: decision)
    }
}
