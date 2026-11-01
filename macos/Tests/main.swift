import Foundation
import NetworkExtension

var tests = 0
func expect(_ condition: @autoclosure () throws -> Bool, _ message: String) {
    tests += 1
    let passed: Bool
    do { passed = try condition() } catch { FileHandle.standardError.write(Data("FAIL: \(message): \(error)\n".utf8)); exit(1) }
    if !passed {
        FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8)); exit(1)
    }
}
func rejects(_ message: String, _ body: () throws -> Void) {
    do { try body(); expect(false, message) } catch { expect(true, message) }
}
/// Also checks which check refused it, for inputs that more than one check would refuse.
func rejects(_ message: String, reason: String, _ body: () throws -> Void) {
    do { try body(); expect(false, message) }
    catch let error as ConfigurationError { expect(error.description == reason, "\(message) (got \(error.description))") }
    catch { expect(false, "\(message) (got \(error))") }
}
/// Arrays nested around one integer, at any depth.
struct NestedJSON: Decodable {
    init(from decoder: Decoder) throws {
        if var items = try? decoder.unkeyedContainer() {
            while !items.isAtEnd { _ = try items.decode(NestedJSON.self) }
        } else {
            _ = try decoder.singleValueContainer().decode(Int.self)
        }
    }
}
func nestedArrays(_ depth: Int) -> Data {
    Data((String(repeating: "[", count: depth) + "0" + String(repeating: "]", count: depth)).utf8)
}
func policy(_ network: String) throws -> NetworkPolicy {
    try NetworkPolicy(data: Data("{\"version\":\"blackice.policy/v0\",\"network\":\(network)}".utf8))
}
func ip(_ text: String) -> IPAddress { IPAddress(text)! }
func configuration(policy text: String = "{\"mode\":\"deny-all\"}", gen: UInt32 = 1,
                   unmatched: String = "allow", hostnameMode: String = "ip-only") throws -> (Data, AppConfiguration) {
    let doc = AppConfigurationDocument(generation: gen, unmatched: unmatched, hostnameMode: hostnameMode,
        apps: [AppBindingDocument(scope: "app-probe", teamID: "ABCDE12345", signingID: "com.example.probe",
            policyJSON: "{\"version\":\"blackice.policy/v0\",\"network\":\(text)}")])
    let data = try JSONEncoder().encode(doc)
    return (data, try AppConfiguration(data: data))
}
let probe = SigningIdentity(signingID: "com.example.probe", teamID: "ABCDE12345")
func flow(app: SigningIdentity? = probe, process: SigningIdentity? = probe, hostname: String? = nil,
          address: String? = "198.51.100.8", port: UInt16? = 443, supported: Bool = true,
          direction: FlowFacts.Direction = .outbound, resolution: IdentityResolution? = nil, tcp: Bool = true) -> FlowFacts {
    FlowFacts(direction: direction, app: resolution ?? app.map(IdentityResolution.verified) ?? .unresolved,
              process: process.map(IdentityResolution.verified) ?? .unresolved, supportedSocket: supported, isTCP: tcp,
              hostname: hostname, ip: address.flatMap { IPAddress($0) }, port: port)
}

do {
    // Reference cases from src/core/policy.zig, plus adapter-specific adversarial cases.
    let allow = try policy(#"{"mode":"allowlist","allow":["Example.COM.","*.npmjs.org"]}"#)
    for host in ["example.com", "registry.npmjs.org", "a.b.npmjs.org"] {
        expect(allow.checkHost(host).allowed, "reference allowed host \(host)")
    }
    for host in ["www.example.com", "npmjs.org", "evilnpmjs.org", "example.com.attacker.test"] {
        expect(!allow.checkHost(host).allowed, "exact/wildcard boundary \(host)")
    }
    expect(allow.id.count == 12, "12 hex policy digest")
    let raw = Data(#"{"version":"blackice.policy/v0","network":{"mode":"deny-all"}}"#.utf8)
    expect(try NetworkPolicy(data: raw).id == digestID(raw), "hash original bytes")
    expect(try NetworkPolicy(data: raw).sha256 == "f9789c9c9a6702d0db5723bad39cbfb2bfee0c7d786e71924d9373a84826e999", "full original-byte SHA-256 vector")
    expect(try NetworkPolicy(data: raw + Data([10])).id != digestID(raw), "whitespace changes byte digest")
    let deny = try policy(#"{"mode":"deny-all","subnets":{"allow":["0.0.0.0/0"]}}"#)
    expect(!deny.checkLiteral(ip("198.51.100.1")).allowed, "deny-all wins subnet")
    let all = try policy(#"{"mode":"allow-all"}"#)
    expect(all.checkLiteral(ip("93.184.216.34")).allowed, "public allow-all")
    for local in ["0.1.2.3", "127.8.2.1", "10.2.3.4", "100.64.1.1", "169.254.169.254", "172.31.0.1",
                  "192.168.1.1", "192.0.0.1", "198.18.0.1", "224.0.0.1", "255.255.255.255", "::", "::1",
                  "fc00::1", "fe80::1", "fec0::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.2.3.4"] {
        expect(all.checkLiteral(ip(local)).reason == "local_or_private_address", "local guard \(local)")
    }
    expect(IPAddress("127.1") == nil && IPAddress("0177.0.0.1") == nil, "ambiguous IPv4 rejected")
    expect(IPAddress("198.51.100.2\0evil") == nil, "NUL address rejected")
    let subnets = try policy(#"{"mode":"allowlist","subnets":{"allow":["10.20.0.0/16","2001:db8:1::/48"],"deny":["10.20.30.0/24"]}}"#)
    expect(subnets.checkLiteral(ip("10.20.1.2")).reason == "allowed_subnet", "explicit private allow")
    expect(subnets.checkLiteral(ip("::ffff:10.20.30.2")).reason == "denied_subnet", "mapped deny beats allow")
    expect(subnets.checkLiteral(ip("2001:db8:1::12")).allowed, "IPv6 allow")
    expect(!subnets.checkLiteral(ip("2001:db8:2::12")).allowed, "IPv6 prefix boundary")
    expect(!allow.checkLiteral(ip("93.184.216.34")).allowed, "no invented name for raw IP")
    expect(try CIDR("0.0.0.0/0").contains(ip("198.51.100.1")), "zero prefix")
    expect(try CIDR("198.51.100.8/32").contains(ip("198.51.100.8")), "exact prefix")
    expect(try !CIDR("198.51.100.8/32").contains(ip("198.51.100.9")), "exact prefix miss")
    expect(normalizeHost("API.Example.COM.") == "api.example.com", "normalize ASCII case and trailing dot")
    for invalid in ["", "a..b", ".a", "bad host", "éxample.com", String(repeating: "a", count: 64) + ".com"] {
        expect(normalizeHost(invalid) == nil, "invalid hostname")
    }
    let malformed = [
        #"{"version":"v9","network":{"mode":"allowlist"}}"#,
        #"{"version":"blackice.policy/v0","network":{"mode":"allowlist","alow":["x.com"]}}"#,
        #"{"version":"blackice.policy/v0","network":{"mode":"deny-all","mode":"allow-all"}}"#,
        #"{"version":"blackice.policy/v0","network":{"mode":"deny-all","\u006dode":"allow-all"}}"#,
        #"{"version":"blackice.policy/v0","network":{"mode":"other"}}"#,
        #"{"version":"blackice.policy/v0","network":{"mode":"allowlist","ports":[0]}}"#,
        #"{"version":"blackice.policy/v0","network":{"mode":"allowlist","ports":[65536]}}"#,
        #"{"version":"blackice.policy/v0","network":{"mode":"allowlist","ports":[true]}}"#,
        #"{"version":"blackice.policy/v0","network":{"mode":"allowlist","allow":null}}"#,
        #"{"version":"blackice.policy/v0","network":{"mode":"allowlist","ports":[443.5]}}"#,
        #"{"version":"blackice.policy/v0","network":{"mode":"allowlist","subnets":{"alow":[]}}}"#
    ]
    for text in malformed { rejects("invalid JSON policy") { _ = try NetworkPolicy(data: Data(text.utf8)) } }
    for pattern in ["*", "www.*.com", "1.2.3.4", "*.1.2.3.4", "a.*.com", "a\0b.com", "2130706433", "127.1", "0x7f000001", "foo.0x"] {
        rejects("invalid pattern \(pattern)") { _ = try DomainPattern(pattern) }
    }
    for subnet in ["1.2.3.4/33", "::/129", "::ffff:127.0.0.1/129", "1.2.3.4/-1", "1.2.3.4/", "0/0", "1.2.3.4/0000"] {
        rejects("invalid subnet") { _ = try CIDR(subnet) }
    }
    // Valid JSON on both sides of each limit, so only the limit can refuse it.
    let padded = raw + Data(repeating: 32, count: StrictJSON.maximumBytes - raw.count)
    expect(try NetworkPolicy(data: padded).mode == "deny-all", "policy of exactly 1 MiB accepted")
    rejects("oversized policy", reason: "configuration_size") { _ = try NetworkPolicy(data: padded + Data([32])) }
    _ = try StrictJSON.decode(NestedJSON.self, from: nestedArrays(31))
    expect(true, "nesting below the cap accepted")
    rejects("nesting cap", reason: "json_nesting_limit") { _ = try StrictJSON.decode(NestedJSON.self, from: nestedArrays(32)) }
    rejects("empty ports rejected by v0 contract") { _ = try policy(#"{"mode":"allow-all","ports":[]}"#) }
    expect(try policy(#"{"mode":"allow-all","ports":null}"#).checkPort(443).reason == "allowed_port", "nullable ports defaults as core")
    expect(allow.checkPort(443).allowed && allow.checkPort(80).allowed && !allow.checkPort(22).allowed, "default ports")
    expect(allow.evaluate(hostname: "example.com", ip: ip("127.0.0.1"), port: 443).reason == "local_or_private_address", "allowed name cannot bypass IP guard")
    expect(allow.evaluate(hostname: "example.com", ip: nil, port: 443).reason == "missing_destination", "name alone never enough")
    expect(allow.evaluate(hostname: "example.com", ip: ip("93.184.216.34"), port: nil).reason == "missing_destination", "port required")
    expect(allow.evaluate(hostname: "example.com", ip: ip("93.184.216.34"), port: 22).reason == "port_not_allowed", "port before domain")
    expect(allow.evaluate(hostname: "example.com", ip: ip("93.184.216.34"), port: 443).allowed, "OS name with checked endpoint")
    let transitionPolicy = try policy(#"{"mode":"allow-all","subnets":{"deny":["203.0.113.0/24","::ffff:198.51.100.0/120"]}}"#)
    expect(transitionPolicy.checkLiteral(ip("64:ff9b::cb00:7109")).reason == "denied_subnet", "NAT64 IPv4 deny")
    expect(transitionPolicy.checkResolved(ip("64:ff9b::7f00:1")).reason == "local_or_private_address", "NAT64 loopback cannot bypass guard")
    expect(transitionPolicy.checkLiteral(ip("64:ff9b::a00:1")).reason == "local_or_private_address", "NAT64 private guard")
    expect(transitionPolicy.checkResolved(ip("64:ff9b::5db8:d822")).reason == "public_address", "NAT64 public classification")
    for address in ["198.51.100.7", "::ffff:198.51.100.7", "::ffff:203.0.113.1"] {
        expect(transitionPolicy.checkLiteral(ip(address)).reason == "denied_subnet", "mapped CIDR deny")
    }
    for address in ["2002:cb00:7109::1", "::cb00:7109", "::ffff:0:cb00:7109", "2001::1"] {
        expect(all.checkResolved(ip(address)).reason == "transition_address", "transition default deny")
    }
    for address in ["64:ff9b:1::1", "100::1"] {
        expect(all.checkResolved(ip(address)).reason == "local_or_private_address", "reserved IPv6 default deny")
    }
    let v6Only = try policy(#"{"mode":"allowlist","subnets":{"allow":["::/0"]}}"#)
    expect(v6Only.checkLiteral(ip("::ffff:127.0.0.1")).reason == "local_or_private_address", "IPv6 wildcard does not permit mapped IPv4")
    expect(v6Only.checkLiteral(ip("93.184.216.34")).reason == "ip_literal_needs_subnet", "IPv6 wildcard does not permit IPv4")
    expect(v6Only.checkLiteral(ip("2606:4700::1111")).allowed, "IPv6 wildcard applies to IPv6")
    let transitionsAllowed = try policy(#"{"mode":"allow-all","subnets":{"allow":["2001::/32","2002::/16","::cb00:7109/128","::ffff:0:cb00:7109/128"]}}"#)
    for address in ["2001:0:4136:e378:8000:63bf:3fff:fdd2", "2002:cb00:7109::1", "::cb00:7109", "::ffff:0:cb00:7109"] {
        expect(transitionsAllowed.checkResolved(ip(address)).reason == "allowed_subnet", "explicit subnet precedes transition classification")
    }
    for mode in ["deny-all", "allow-all", "allowlist"] {
        let p = try policy("{\"mode\":\"\(mode)\",\"ports\":[443]}")
        expect(p.evaluate(hostname: "2130706433", ip: ip("93.184.216.34"), port: 22).reason == "port_not_allowed", "port checked before mode/name")
    }
    for host in ["2130706433", "127.1", "0x7f000001", "0X7F.1", "0177.0.0.1", "1.2.3.4.", "foo.0x"] {
        expect(normalizeHost(host) == nil, "core numeric-name normalization vector")
    }

    let (_, config) = try configuration()
    expect(!AppEvaluator.evaluate(flow(), configuration: config).decision.allowed, "enrolled app deny")
    expect(AppEvaluator.evaluate(flow(app: nil), configuration: config).decision.reason == "unknown_app_identity", "unknown app denied despite unmatched allow")
    expect(AppEvaluator.evaluate(flow(app: SigningIdentity(signingID: probe.signingID, teamID: "OTHER12345")), configuration: config).decision.reason == "outside_scope", "identifier without correct team never enrolls")
    expect(!AppEvaluator.evaluate(flow(), configuration: nil).decision.allowed, "missing configuration denies")
    expect(AppEvaluator.evaluate(flow(direction: .inbound), configuration: config).decision.reason == "inbound_not_allowed", "bound inbound denies")
    expect(!AppEvaluator.evaluate(flow(direction: .unknown), configuration: config).decision.allowed, "unknown direction denied")
    expect(AppEvaluator.evaluate(flow(supported: false), configuration: config).decision.reason == "unsupported_socket", "unknown socket denies")
    expect(!AppEvaluator.evaluate(flow(process: SigningIdentity(signingID: "com.apple.service", teamID: nil)), configuration: config).decision.allowed, "delegated process cannot replace source app policy")
    let (_, unboundDeny) = try configuration(unmatched: "deny")
    expect(!AppEvaluator.evaluate(flow(app: SigningIdentity(signingID: "com.other", teamID: "OTHER12345")), configuration: unboundDeny).decision.allowed, "explicit unmatched deny")
    let (_, domainConfig) = try configuration(policy: #"{"mode":"allowlist","allow":["example.com"]}"#, hostnameMode: "os-metadata")
    expect(!AppEvaluator.evaluate(flow(address: "93.184.216.34"), configuration: domainConfig).decision.allowed, "hostname absence cannot match domain")
    expect(AppEvaluator.evaluate(flow(hostname: "example.com", address: "93.184.216.34"), configuration: domainConfig).decision.allowed, "explicit metadata mode")
    rejects("domain policy unsupported in IP-only mode") { _ = try configuration(policy: #"{"mode":"allowlist","allow":["example.com"]}"#) }
    rejects("explicit unmatched required") { _ = try configuration(unmatched: "") }
    rejects("generation zero rejected") { _ = try configuration(gen: 0) }
    let (document, _) = try configuration()
    var object = try JSONSerialization.jsonObject(with: document) as! [String: Any]
    object["unknown_identity"] = "allow"
    rejects("unknown selector rejected") { _ = try AppConfiguration(data: JSONSerialization.data(withJSONObject: object)) }
    object.removeValue(forKey: "unknown_identity")
    let bindings = object["apps"] as! [[String: Any]]
    expect(object["version"] as? String == "blackice.appscope/v0", "approved wrapper version")
    expect(bindings[0]["policy_sha256"] as? String == digestHex(raw), "wrapper embeds full SHA-256")
    var modified = object
    modified["version"] = "blackice.apps/v0"
    rejects("old wrapper name rejected") { _ = try AppConfiguration(data: JSONSerialization.data(withJSONObject: modified)) }
    for value in [String(repeating: "0", count: 64), digestHex(raw).uppercased(), String(digestHex(raw).prefix(12))] {
        var edited = bindings[0]
        edited["policy_sha256"] = value
        modified = object
        modified["apps"] = [edited]
        rejects("invalid or mismatched full digest rejected") { _ = try AppConfiguration(data: JSONSerialization.data(withJSONObject: modified)) }
    }
    var edited = bindings[0]
    edited.removeValue(forKey: "policy_sha256")
    modified = object
    modified["apps"] = [edited]
    rejects("digest required") { _ = try AppConfiguration(data: JSONSerialization.data(withJSONObject: modified)) }
    edited = bindings[0]
    edited["policy_json"] = (edited["policy_json"] as! String) + "\n"
    modified["apps"] = [edited]
    rejects("policy byte change invalidates digest") { _ = try AppConfiguration(data: JSONSerialization.data(withJSONObject: modified)) }
    edited["policy_sha256"] = digestHex(Data((edited["policy_json"] as! String).utf8))
    modified["apps"] = [edited]
    expect(try AppConfiguration(data: JSONSerialization.data(withJSONObject: modified)).apps[0].policy.sha256 == edited["policy_sha256"] as? String, "matching digest preserves changed original bytes")
    object["apps"] = bindings + bindings
    rejects("duplicate binding rejected") { _ = try AppConfiguration(data: JSONSerialization.data(withJSONObject: object)) }
    for scope in ["app-unbound", "app-unavailable", "app-provider", "app-control"] {
        var named = bindings[0]
        named["scope"] = scope
        modified = object
        modified["apps"] = [named]
        rejects("binding cannot take the receipt scope \(scope)", reason: "reserved_scope") {
            _ = try AppConfiguration(data: JSONSerialization.data(withJSONObject: modified))
        }
    }
    expect(AppFilterConstants.reservedScopes.contains(AppEvaluator.evaluate(flow(), configuration: nil).scope) &&
           AppFilterConstants.reservedScopes.contains(AppEvaluator.evaluate(flow(app: SigningIdentity(signingID: "com.other", teamID: "OTHER12345")), configuration: config).scope),
           "evaluator scopes for unbound and unavailable are reserved")
    expect(!validTeamID("A\" OR true") && !validSigningID("com.a\" or true"), "requirement injection rejected")
    let snapshots = SnapshotStore()
    try snapshots.install(config)
    try snapshots.install(config)
    let (_, changed) = try configuration(policy: #"{"mode":"allow-all"}"#)
    rejects("same generation different policy rejected") { try snapshots.install(changed) }
    expect(snapshots.read()?.id == config.id, "failed update retains snapshot")
    let (_, second) = try configuration(gen: 2)
    try snapshots.install(second)
    rejects("stale generation rejected") { try snapshots.install(config) }
    snapshots.clear()
    expect(snapshots.read() == nil, "stop clears snapshot")

    expect(CodeIdentity.resolve(auditToken: nil) == .unresolved, "missing audit token rejected")
    expect(CodeIdentity.resolve(auditToken: Data([1, 2])) == .unresolved, "invalid audit token length rejected")
    expect(CodeIdentity.resolve(auditToken: Data(repeating: 0, count: 32)) == .unresolved, "invalid audit token rejected by Security")
    expect(CodeIdentity.current() == nil, "ad hoc test binary not trusted app identity")
    expect(NSClassFromString("BlackiceFilter.FilterDataProvider") != nil, "Info.plist runtime provider class resolves")
    let settings = FilterDataProvider.makeSettings()
    expect(settings.defaultAction == .filterData, "default flow delivery to provider")
    expect(settings.rules.count == 3 && settings.rules.allSatisfy { $0.action == .filterData }, "loopback has explicit callback rules")
    let facts = flow(process: SigningIdentity(signingID: "com.apple.service", teamID: nil))
    let receipt = Receipt.flow(facts, result: AppEvaluator.evaluate(facts, configuration: config), hostnameMode: "ip-only")
    let line = try receipt.jsonLine()
    let json = try JSONSerialization.jsonObject(with: Data(line.utf8)) as! [String: Any]
    expect(line.filter { $0 == "\n" }.count == 1, "one newline per receipt")
    expect(json["host"] == nil && json["rule"] == nil, "null receipt fields omitted")
    expect(json["point"] as? String == "app_filter", "Network Extension receipt point contract")
    expect(json["scope"] as? String == "app-probe" && json["gen"] as? Int == 1, "app scope and generation")
    expect((json["detail"] as? String)?.contains("process=apple/com.apple.service") == true, "separate process identity in receipt")
    expect(Set(json.keys).isSubset(of: ["ts", "scope", "policy", "gen", "point", "event", "verdict", "reason", "rule", "host", "ip", "port", "status", "dropped", "detail"]), "flat core receipt schema")
    expect(Receipt.clean("a\u{1b}b\u{202e}c", limit: 16) == "a?b?c", "receipt control and bidi cleaning")
    expect(Receipt.clean("0123456789abñññ", limit: 16) == "0123456789ab...", "receipt UTF-8 boundary truncation")
    let cleaningVectors: [(Data, String)] = [
        (Data([0x61, 0x1b, 0x62, 0xff, 0x63]), "a?b?c"),
        (Data("ñandú".utf8), "ñandú"),
        (Data("0123456789abcdef".utf8), "0123456789abcdef"),
        (Data("0123456789abcdefg".utf8), "0123456789abc..."),
        (Data([0xc0, 0xaf]), "??"),
        (Data([0xed, 0xa0, 0x80]), "???"),
        (Data([0xf4, 0x90, 0x80, 0x80]), "????"),
        (Data([0xe2, 0x82]), "??"),
        (Data([0xef, 0xbb, 0xbf]), "?"),
        (Data("x\u{85}\u{200b}\u{202e}\u{2066}y".utf8), "x????y")
    ]
    for (input, expected) in cleaningVectors {
        expect(Receipt.clean(input, limit: 16) == expected, "core receipt byte-cleaning vector")
    }
    var oversized = receipt
    oversized.event = String(repeating: "\"", count: 8192)
    oversized.host = String(repeating: "\"", count: 8192)
    oversized.reason = String(repeating: "\u{1b}", count: 8192)
    oversized.rule = String(repeating: "\\", count: 8192)
    oversized.ip = String(repeating: "\u{202e}", count: 8192)
    oversized.detail = String(repeating: "\"", count: 8192)
    let capped = try oversized.jsonLine()
    expect(capped.utf8.count < 4096, "large receipt fields fit core line cap")
    let cappedObject = try JSONSerialization.jsonObject(with: Data(capped.utf8)) as! [String: Any]
    expect((cappedObject["detail"] as? String)?.utf8.count == 512, "core detail byte cap")
    try securityRegressions()
    try identityCacheRegressions()
    print("PASS: \(tests) assertions (policy, app scope, identity, user presence, TLS, privacy, snapshots, receipts)")
    print("Unit tests only. No Network Extension was activated; no live enforcement is claimed.")
} catch { FileHandle.standardError.write(Data("Unexpected test error: \(error)\n".utf8)); exit(1) }
