import CryptoKit
import Darwin
import Foundation

struct Decision: Equatable {
    let allowed: Bool
    let reason: String
    var rule: String? = nil
}

struct IPAddress: Equatable {
    /// IPv4-mapped IPv6 is normalized to IPv4 for both CIDRs and destinations.
    let bytes: [UInt8]

    init(bytes: [UInt8]) { self.bytes = bytes }

    init?(_ text: String, normalizeMapped: Bool = true) {
        guard !text.utf8.contains(0) else { return nil }
        // Darwin inet_pton accepts some leading-zero forms. Validate dotted
        // decimal ourselves, also when embedded in an IPv6 address.
        if text.contains(".") {
            let dotted = text.split(separator: ":", omittingEmptySubsequences: false).last ?? ""
            let labels = dotted.split(separator: ".", omittingEmptySubsequences: false)
            guard labels.count == 4, labels.allSatisfy({ label in
                !label.isEmpty && label.utf8.count <= 3 &&
                    label.utf8.allSatisfy { (48...57).contains($0) } &&
                    !(label.count > 1 && label.first == "0") && UInt8(label) != nil
            }) else { return nil }
        } else if !text.contains(":") { return nil }
        var v4 = in_addr()
        if text.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            bytes = withUnsafeBytes(of: v4) { Array($0) }
            return
        }
        var v6 = in6_addr()
        guard text.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 else { return nil }
        let raw = withUnsafeBytes(of: v6) { Array($0) }
        bytes = normalizeMapped && raw.prefix(10).allSatisfy { $0 == 0 } && raw[10] == 255 && raw[11] == 255
            ? Array(raw.suffix(4)) : raw
    }

    var text: String {
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let family = bytes.count == 4 ? AF_INET : AF_INET6
        let result = bytes.withUnsafeBytes {
            inet_ntop(family, $0.baseAddress, &buffer, socklen_t(buffer.count))
        }
        return result == nil ? "" : String(cString: buffer)
    }

    var isMapped: Bool {
        bytes.count == 16 && bytes.prefix(10).allSatisfy { $0 == 0 } && bytes[10] == 255 && bytes[11] == 255
    }

    var isNAT64: Bool {
        bytes.count == 16 && Array(bytes.prefix(12)) == [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    var matchingAddresses: [IPAddress] {
        if isMapped { return [IPAddress(bytes: Array(bytes.suffix(4)))] }
        if isNAT64 { return [self, IPAddress(bytes: Array(bytes.suffix(4)))] }
        return [self]
    }

    enum AddressClass { case `public`, local, transition }

    var classification: AddressClass {
        let b = bytes
        if b.count == 4 {
            let local = b[0] == 0 || b[0] == 10 || b[0] == 127 ||
                (b[0] == 100 && b[1] & 0xc0 == 64) ||
                (b[0] == 169 && b[1] == 254) ||
                (b[0] == 172 && b[1] & 0xf0 == 16) ||
                (b[0] == 192 && b[1] == 0 && b[2] == 0) ||
                (b[0] == 192 && b[1] == 168) ||
                (b[0] == 198 && b[1] & 0xfe == 18) || b[0] >= 224
            return local ? .local : .public
        }
        if isMapped || isNAT64 { return IPAddress(bytes: Array(b.suffix(4))).classification }
        if b.prefix(15).allSatisfy({ $0 == 0 }) && b[15] <= 1 { return .local }
        if b.prefix(12).allSatisfy({ $0 == 0 }) { return .transition }
        if b.prefix(8).allSatisfy({ $0 == 0 }) && Array(b[8..<12]) == [255, 255, 0, 0] { return .transition }
        if Array(b.prefix(6)) == [0, 0x64, 0xff, 0x9b, 0, 1] { return .local }
        if b[0] == 1 && b[1] == 0 && b[2..<8].allSatisfy({ $0 == 0 }) { return .local }
        if b[0] & 0xfe == 0xfc || (b[0] == 0xfe && b[1] & 0xc0 == 0x80) ||
            (b[0] == 0xfe && b[1] & 0xc0 == 0xc0) || b[0] == 0xff { return .local }
        if b[0] == 0x20 && b[1] == 2 { return .transition }
        if Array(b.prefix(4)) == [0x20, 1, 0, 0] { return .transition }
        return .public
    }
}

struct CIDR {
    let address: IPAddress
    let prefix: Int
    let source: String

    init(_ source: String) throws {
        let parts = source.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let parsed = IPAddress(String(parts[0]), normalizeMapped: false),
              !parts[1].isEmpty, parts[1].utf8.count <= 3,
              parts[1].utf8.allSatisfy({ (48...57).contains($0) }),
              let prefix = Int(parts[1]), prefix <= parsed.bytes.count * 8 else {
            throw ConfigurationError.invalid("invalid_subnet")
        }
        self.source = source
        self.address = parsed.isMapped && prefix >= 96 ? IPAddress(bytes: Array(parsed.bytes.suffix(4))) : parsed
        self.prefix = parsed.isMapped && prefix >= 96 ? prefix - 96 : prefix
    }

    func contains(_ other: IPAddress) -> Bool {
        other.matchingAddresses.contains(where: matches)
    }

    private func matches(_ other: IPAddress) -> Bool {
        guard address.bytes.count == other.bytes.count else { return false }
        let full = prefix / 8, remaining = prefix % 8
        guard address.bytes.prefix(full) == other.bytes.prefix(full) else { return false }
        if remaining == 0 { return true }
        let mask = UInt8(truncatingIfNeeded: 0xff << (8 - remaining))
        return address.bytes[full] & mask == other.bytes[full] & mask
    }
}

func looksNumeric(_ text: String) -> Bool {
    let last = text.split(separator: ".", omittingEmptySubsequences: false).last ?? ""
    guard !last.isEmpty else { return false }
    if last.lowercased().hasPrefix("0x") {
        return last.dropFirst(2).utf8.allSatisfy { (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }
    }
    return last.utf8.allSatisfy { (48...57).contains($0) }
}

func normalizeHost(_ raw: String) -> String? {
    let text = raw.hasSuffix(".") ? String(raw.dropLast()) : raw
    guard !text.isEmpty, text.utf8.count <= 253 else { return nil }
    var labelLength = 0
    for c in text.utf8 {
        switch c {
        case 65...90, 97...122, 48...57, 45, 95: labelLength += 1
        case 46:
            guard labelLength > 0 else { return nil }
            labelLength = 0
        default: return nil
        }
        if labelLength > 63 { return nil }
    }
    return labelLength > 0 && !looksNumeric(text) ? text.lowercased() : nil
}

struct DomainPattern {
    let source: String
    let suffix: String
    let wildcard: Bool

    init(_ source: String) throws {
        let wildcard = source.hasPrefix("*.")
        let base = wildcard ? String(source.dropFirst(2)) : source
        guard let host = normalizeHost(base), IPAddress(host) == nil else {
            throw ConfigurationError.invalid("invalid_pattern")
        }
        self.source = source
        self.wildcard = wildcard
        self.suffix = wildcard ? "." + host : host
    }

    func matches(_ host: String) -> Bool {
        wildcard ? host.count > suffix.count && host.hasSuffix(suffix) : host == suffix
    }
}

private struct RawSubnets: Decodable {
    var allow: [String] = []
    var deny: [String] = []
    enum CodingKeys: String, CodingKey { case allow, deny }
    init() {}
    init(from decoder: Decoder) throws {
        try decoder.rejectUnknownKeys(["allow", "deny"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        allow = try c.decodeOrDefault([String].self, forKey: .allow, default: [])
        deny = try c.decodeOrDefault([String].self, forKey: .deny, default: [])
    }
}

private struct RawNetwork: Decodable {
    let mode: String
    let allow: [String]
    let subnets: RawSubnets
    let ports: [UInt16]
    enum CodingKeys: String, CodingKey { case mode, allow, subnets, ports }
    init(from decoder: Decoder) throws {
        try decoder.rejectUnknownKeys(["mode", "allow", "subnets", "ports"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        mode = try c.decode(String.self, forKey: .mode)
        allow = try c.decodeOrDefault([String].self, forKey: .allow, default: [])
        subnets = try c.decodeOrDefault(RawSubnets.self, forKey: .subnets, default: RawSubnets())
        // The core's nullable ports field treats null like omission.
        ports = try c.decodeIfPresent([UInt16].self, forKey: .ports) ?? [80, 443]
    }
}

private struct RawPolicy: Decodable {
    let version: String
    let network: RawNetwork
    enum CodingKeys: String, CodingKey { case version, network }
    init(from decoder: Decoder) throws {
        try decoder.rejectUnknownKeys(["version", "network"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(String.self, forKey: .version)
        network = try c.decode(RawNetwork.self, forKey: .network)
    }
}

func digestHex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

func digestID(_ data: Data) -> String { String(digestHex(data).prefix(12)) }

/// Same policy version, byte digest, precedence and reasons as src/core/policy.zig.
struct NetworkPolicy {
    let sha256: String
    var id: String { String(sha256.prefix(12)) }
    let mode: String
    let patterns: [DomainPattern]
    let allowSubnets: [CIDR]
    let denySubnets: [CIDR]
    let ports: Set<UInt16>

    init(data: Data) throws {
        let raw = try StrictJSON.decode(RawPolicy.self, from: data)
        guard raw.version == "blackice.policy/v0" else {
            throw ConfigurationError.invalid("unsupported_policy_version")
        }
        guard ["deny-all", "allow-all", "allowlist"].contains(raw.network.mode) else {
            throw ConfigurationError.invalid("unknown_mode")
        }
        guard raw.network.allow.count <= 256, raw.network.subnets.allow.count <= 256,
              raw.network.subnets.deny.count <= 256, raw.network.ports.count <= 65535,
              !raw.network.ports.isEmpty, !raw.network.ports.contains(0) else {
            throw ConfigurationError.invalid("policy_limit_or_invalid_port")
        }
        sha256 = digestHex(data)
        mode = raw.network.mode
        patterns = try raw.network.allow.map(DomainPattern.init)
        allowSubnets = try raw.network.subnets.allow.map(CIDR.init)
        denySubnets = try raw.network.subnets.deny.map(CIDR.init)
        ports = Set(raw.network.ports)
    }

    func checkPort(_ port: UInt16) -> Decision {
        ports.contains(port) ? Decision(allowed: true, reason: "allowed_port") :
            Decision(allowed: false, reason: "port_not_allowed")
    }

    func checkHost(_ host: String) -> Decision {
        if looksNumeric(host) || host.contains(":") { return Decision(allowed: false, reason: "invalid_host") }
        if mode == "deny-all" { return Decision(allowed: false, reason: "mode_deny_all") }
        if mode == "allow-all" { return Decision(allowed: true, reason: "allowed_by_mode") }
        if let pattern = patterns.first(where: { $0.matches(host) }) {
            return Decision(allowed: true, reason: "allowed_by_rule", rule: pattern.source)
        }
        return Decision(allowed: false, reason: "no_matching_rule")
    }

    func checkResolved(_ ip: IPAddress) -> Decision {
        if let subnet = denySubnets.first(where: { $0.contains(ip) }) {
            return Decision(allowed: false, reason: "denied_subnet", rule: subnet.source)
        }
        if let subnet = allowSubnets.first(where: { $0.contains(ip) }) {
            return Decision(allowed: true, reason: "allowed_subnet", rule: subnet.source)
        }
        switch ip.classification {
        case .local: return Decision(allowed: false, reason: "local_or_private_address")
        case .transition: return Decision(allowed: false, reason: "transition_address")
        case .public: return Decision(allowed: true, reason: "public_address")
        }
    }

    func checkLiteral(_ ip: IPAddress) -> Decision {
        if mode == "deny-all" { return Decision(allowed: false, reason: "mode_deny_all") }
        let verdict = checkResolved(ip)
        if !verdict.allowed || verdict.reason == "allowed_subnet" { return verdict }
        return mode == "allow-all" ? verdict : Decision(allowed: false, reason: "ip_literal_needs_subnet")
    }

    /// No DNS, reverse lookup, SNI or URL inference. Missing name uses IP policy.
    func evaluate(hostname: String?, ip: IPAddress?, port: UInt16?) -> Decision {
        guard let port, port > 0 else { return Decision(allowed: false, reason: "missing_destination") }
        let portDecision = checkPort(port)
        guard portDecision.allowed else { return portDecision }
        if mode == "deny-all" { return Decision(allowed: false, reason: "mode_deny_all") }
        guard let ip else { return Decision(allowed: false, reason: "missing_destination") }
        guard let hostname else { return checkLiteral(ip) }
        // Address-looking metadata is not evidence for a domain rule.
        if IPAddress(hostname) != nil { return checkLiteral(ip) }
        guard let host = normalizeHost(hostname) else { return Decision(allowed: false, reason: "invalid_host") }
        let hostDecision = checkHost(host)
        guard hostDecision.allowed else { return hostDecision }
        let ipDecision = checkResolved(ip)
        return ipDecision.allowed ? hostDecision : ipDecision
    }
}
