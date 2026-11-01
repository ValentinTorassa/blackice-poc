import Foundation

/// Kept in sync with src/core/receipt.zig: receipt.limits.
enum ReceiptLimits {
    static let event = 32, reason = 64, rule = 256, host = 256, ip = 64, detail = 512
}

/// Flat src/core/receipt.zig schema. No payloads, URLs, tokens, paths or environment.
struct Receipt: Encodable {
    let ts: String
    let scope: String
    let policy: String
    let gen: UInt32
    let point: String
    var event: String
    var verdict: String? = nil
    var reason: String? = nil
    var rule: String? = nil
    var host: String? = nil
    var ip: String? = nil
    var port: UInt16? = nil
    var status: UInt8? = nil
    var dropped: UInt64? = nil
    var detail: String? = nil

    init(scope: String, policy: String, generation: UInt32, point: String, event: String, date: Date = Date()) {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        ts = formatter.string(from: date)
        self.scope = scope; self.policy = policy; gen = generation; self.point = point; self.event = event
    }

    static func flow(_ flow: FlowFacts, result: AppDecision, hostnameMode: String?) -> Receipt {
        var receipt = Receipt(scope: result.scope, policy: result.policy, generation: result.generation,
                              point: "app_filter", event: "connect")
        receipt.verdict = result.decision.allowed ? "allow" : "deny"
        receipt.reason = result.decision.reason
        receipt.rule = result.decision.rule
        // Only normalized, bounded host metadata; never serialize arbitrary URL text.
        receipt.host = flow.hostname.flatMap(normalizeHost)
        receipt.ip = flow.ip?.text
        receipt.port = flow.port
        receipt.detail = "backend=network_extension;scope_kind=app;" + (result.echPresent ? "ech_present;" : "") +
            "app=\(identityLabel(flow.app));" +
            "process=\(identityLabel(flow.process));hostname_source=\(flow.hostname == nil ? "absent" : "os_metadata");" +
            "hostname_mode=\(hostnameMode ?? "unavailable")"
        return receipt
    }

    private static func identityLabel(_ identity: IdentityResolution) -> String {
        let label = identity.label
        // Keep both identities and name provenance within the core's 512-byte
        // detail cap. Long ASCII identifiers retain a hash of the complete label.
        return label.utf8.count <= 128 ? label : String(label.prefix(112)) + "...#" + digestID(Data(label.utf8))
    }

    /// Strings already contain valid Unicode; raw-byte cleaning below also
    /// preserves the core's behavior for malformed UTF-8 at adapter boundaries.
    static func clean(_ text: String, limit: Int) -> String {
        clean(Data(text.utf8), limit: limit)
    }

    static func clean(_ data: Data, limit: Int) -> String {
        precondition(limit >= 4)
        let bytes = Array(data)
        let capacity = bytes.count <= limit ? limit : limit - 3
        var result: [UInt8] = [], index = 0
        while index < bytes.count {
            let width: Int
            switch bytes[index] {
            case 0...0x7f: width = 1
            case 0xc2...0xdf: width = 2
            case 0xe0...0xef: width = 3
            case 0xf0...0xf4: width = 4
            default: width = 1
            }
            var consumed = 1, scalar: UInt32?
            if width == 1 && bytes[index] < 0x80 { scalar = UInt32(bytes[index]) }
            else if width > 1 && index + width <= bytes.count {
                let mask: UInt8 = width == 2 ? 0x1f : (width == 3 ? 0x0f : 0x07)
                var value = UInt32(bytes[index] & mask), valid = true
                for byte in bytes[(index + 1)..<(index + width)] {
                    if byte & 0xc0 != 0x80 { valid = false }
                    value = (value << 6) | UInt32(byte & 0x3f)
                }
                let minimum: UInt32 = width == 2 ? 0x80 : (width == 3 ? 0x800 : 0x10000)
                if valid && value >= minimum && value <= 0x10ffff && !(0xd800...0xdfff).contains(value) {
                    scalar = value
                    consumed = width
                }
            }
            let value = scalar ?? 0
            let control = value <= 0x1f || (0x7f...0x9f).contains(value) ||
                (0x200b...0x200f).contains(value) || (0x2028...0x202e).contains(value) ||
                (0x2060...0x2069).contains(value) || value == 0xfeff
            let keep = scalar != nil && !control
            let length = keep ? consumed : 1
            if result.count + length > capacity {
                result.append(contentsOf: [46, 46, 46]); break
            }
            if keep { result.append(contentsOf: bytes[index..<(index + consumed)]) }
            else { result.append(63) }
            index += consumed
        }
        return String(decoding: result, as: UTF8.self)
    }

    func jsonLine() throws -> String {
        var bounded = self
        bounded.event = Self.clean(event, limit: ReceiptLimits.event)
        bounded.reason = reason.map { Self.clean($0, limit: ReceiptLimits.reason) }
        bounded.rule = rule.map { Self.clean($0, limit: ReceiptLimits.rule) }
        bounded.host = host.map { Self.clean($0, limit: ReceiptLimits.host) }
        bounded.ip = ip.map { Self.clean($0, limit: ReceiptLimits.ip) }
        bounded.detail = detail.map { Self.clean($0, limit: ReceiptLimits.detail) }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(bounded)
        guard data.count < 4096, let text = String(data: data, encoding: .utf8) else {
            throw ConfigurationError.invalid("receipt_size")
        }
        return text + "\n"
    }
}
