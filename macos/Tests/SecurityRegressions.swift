import Foundation

private func word(_ value: Int) -> [UInt8] { [UInt8(value >> 8), UInt8(value & 255)] }

/// Same TLS 1.3 ClientHello shape as src/proxy/test.zig (supported_versions + SNI).
private func clientHello(_ host: String?, extra: [UInt8] = [], duplicateSNI: Bool = false) -> Data {
    var extensions: [UInt8] = [0, 43, 0, 3, 2, 3, 4]
    if let host {
        let name = Array(host.utf8)
        let sni: [UInt8] = [0, 0] + word(name.count + 5) + word(name.count + 3) + [0] + word(name.count) + name
        extensions += sni
        if duplicateSNI { extensions += sni }
    }
    extensions += extra
    var body: [UInt8] = [3, 3] + Array(repeating: 0xab, count: 32)
    body += [0, 0, 2, 0x13, 1, 1, 0]
    body += word(extensions.count) + extensions
    return Data([0x16, 3, 1] + word(body.count + 4) + [1, 0] + word(body.count) + body)
}

private final class FakePresence: PresenceAuthenticating {
    let accepts: Bool
    var reasons: [String] = []
    init(accepts: Bool) { self.accepts = accepts }
    func authenticate(reason: String, completion: @escaping (Bool) -> Void) {
        reasons.append(reason); completion(accepts)
    }
}

func securityRegressions() throws {
    let (_, config) = try configuration()
    let (_, denyUnmatched) = try configuration(unmatched: "deny")
    // Use the actual dynamic code object of this linker's ad hoc test executable.
    expect(CodeIdentity.currentResolution() == .adHoc, "OS-validated ad hoc code resolves distinctly")
    for address in ["93.184.216.34", "127.0.0.1", "::1"] {
        let facts = flow(address: address, resolution: .adHoc)
        let allowed = AppEvaluator.evaluate(facts, configuration: config)
        expect(allowed.decision.allowed && allowed.decision.reason == "outside_scope_adhoc", "ad hoc tools inherit unmatched allow including loopback")
        expect(!AppEvaluator.evaluate(facts, configuration: denyUnmatched).decision.allowed, "ad hoc honors unmatched deny")
    }
    for identity in [IdentityResolution.unresolved, .invalidSignature] {
        expect(!AppEvaluator.evaluate(flow(resolution: identity), configuration: config).decision.allowed, "failed signed identity never gets unmatched allow")
        expect(!AppEvaluator.evaluate(flow(direction: .inbound, resolution: identity), configuration: config).decision.allowed, "unresolved inbound denied")
    }
    let other = SigningIdentity(signingID: "com.other.app", teamID: "OTHER12345")
    let inbound = AppEvaluator.evaluate(flow(app: other, direction: .inbound), configuration: config)
    expect(inbound.decision.allowed && inbound.decision.reason == "outside_scope_inbound", "known unbound inbound follows unmatched")
    expect(!AppEvaluator.evaluate(flow(app: other, direction: .inbound), configuration: denyUnmatched).decision.allowed, "unbound inbound respects unmatched deny")
    let (_, allowAll) = try configuration(policy: #"{"mode":"allow-all"}"#)
    let boundInbound = AppEvaluator.evaluate(flow(direction: .inbound), configuration: allowAll)
    expect(!boundInbound.decision.allowed && boundInbound.decision.reason == "inbound_not_allowed", "allow-all does not open inbound listener")

    for action in HostAction.allCases {
        let reject = FakePresence(accepts: false), accept = FakePresence(accepts: true)
        var mutations = 0, refusals = 0
        var announced: [String] = []
        let prompt = AuthorizationPrompt(action: action, policy: .available(config),
            parent: AuthorizationParent(pid: 42, name: Data("test-shell".utf8)))
        PresenceGate.perform(prompt, using: reject, announce: { announced.append($0) }, denied: { refusals += 1 }, authorized: { mutations += 1 })
        expect(mutations == 0 && refusals == 1, "cancel/unavailable authentication blocks \(action.rawValue)")
        PresenceGate.perform(prompt, using: accept, announce: { announced.append($0) }, denied: { refusals += 1 }, authorized: { mutations += 1 })
        expect(mutations == 1 && refusals == 1 && accept.reasons == [prompt.reason], "successful user presence gates \(action.rawValue)")
        PresenceGate.perform(prompt, using: reject, announce: { announced.append($0) }, denied: { refusals += 1 }, authorized: { mutations += 1 })
        expect(mutations == 1 && refusals == 2 && reject.reasons.count == 2, "previous approval never bypasses later request")
        expect(announced == Array(repeating: prompt.reason, count: 3), "terminal and authentication receive identical complete summary")
        expect(prompt.reason.contains("generation 1") && prompt.reason.contains("unmatched allow") &&
               prompt.reason.contains("configuration sha256 \(config.id)"), "prompt identifies generation, exact wrapper digest and unmatched mode")
        expect(prompt.reason.contains("com.example.probe/ABCDE12345") &&
               prompt.reason.contains("policy sha256 \(config.apps[0].policy.sha256.prefix(12))"), "prompt binds app identity to original policy digest")
        expect(prompt.reason.contains("Parent: test-shell (pid 42, audit only)"), "prompt exposes requesting parent without using it for authorization")
    }
    expect(AuthorizationParent(pid: 42, name: Data("fake\n\u{202e}shell".utf8)).name == "fake??shell", "parent label control/bidi characters cannot forge prompt lines")
    expect(AuthorizationParent.current().pid > 0 && !AuthorizationParent.current().name.isEmpty, "parent label resolves on Mac without an authorization role")
    expect(AuthorizationPolicy.absent.summary.contains("none") && AuthorizationPolicy.unreadable.summary.contains("unknown"), "missing or unreadable saved policy is explicit during recovery")
    let (_, changedPromptPolicy) = try configuration(policy: #"{"mode":"allow-all"}"#, gen: 7, unmatched: "deny")
    let summary = AuthorizationPolicy.available(changedPromptPolicy).summary
    expect(summary.contains("generation 7") && summary.contains("unmatched deny") &&
           summary.contains(String(changedPromptPolicy.apps[0].policy.sha256.prefix(12))) &&
           summary != AuthorizationPolicy.available(config).summary, "policy replacement changes recognizable prompt summary")
    try ConfigurationUpdate.validate(config, replacing: nil)
    rejects("host rejects same-generation replacement") { try ConfigurationUpdate.validate(config, replacing: config) }
    let (_, next) = try configuration(gen: 2)
    try ConfigurationUpdate.validate(next, replacing: config)
    rejects("host rejects rollback") { try ConfigurationUpdate.validate(config, replacing: next) }

    let (_, domains) = try configuration(policy: #"{"mode":"allowlist","allow":["*.example.com"]}"#, hostnameMode: "os-metadata")
    let domain = AppEvaluator.evaluate(flow(hostname: "API.Example.com."), configuration: domains)
    expect(domain.requiredTLSHost == "api.example.com", "domain allow waits for exact normalized SNI")
    let udp = AppEvaluator.evaluate(flow(hostname: "api.example.com", tcp: false), configuration: domains)
    expect(!udp.decision.allowed && udp.decision.reason == "domain_requires_tls_tcp", "domain cannot authorize UDP/QUIC")
    let (_, subnet) = try configuration(policy: #"{"mode":"allowlist","subnets":{"allow":["198.51.100.0/24"]}}"#)
    let udpSubnet = AppEvaluator.evaluate(flow(tcp: false), configuration: subnet)
    expect(udpSubnet.decision.allowed && udpSubnet.requiredTLSHost == nil, "explicit subnet can authorize UDP")
    expect(AppEvaluator.evaluate(flow(hostname: "api.example.com", port: 22), configuration: domains).decision.reason == "port_not_allowed", "port denial precedes TLS gate")
    let hello = clientHello("api.example.com")
    expect(TLSClientHello.inspect(hello) == .serverName("api.example.com"), "proxy ClientHello SNI vector")
    expect(TLSClientHello.inspect(clientHello(nil)) == .deny("sni_missing"), "proxy ClientHello missing SNI vector")
    expect(TLSClientHello.inspect(Data("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n".utf8)) == .deny("not_tls"), "plaintext HTTP never gets domain allow")
    for end in 0..<hello.count {
        guard case .needMore = TLSClientHello.inspect(hello.prefix(end)) else {
            expect(false, "truncated ClientHello must not allow"); return
        }
        expect(true, "truncated ClientHello holds bytes")
    }
    var fragmented = TLSInspection(expectedHost: "api.example.com")
    expect(fragmented.receive(hello.prefix(3), offset: 0) == .needMore(5), "partial header stays held")
    expect(fragmented.receive(hello.prefix(5), offset: 0) == .needMore(hello.count), "cumulative header requests bounded record")
    expect(fragmented.receive(hello.dropFirst(5), offset: 5) == .serverName("api.example.com"), "contiguous TCP slices validate")
    var mismatch = TLSInspection(expectedHost: "api.example.com")
    expect(mismatch.receive(clientHello("evil.example.com"), offset: 0) == .deny("sni_mismatch"), "another wildcard-allowed host on same CDN cannot replace observed hostname")
    var normalized = TLSInspection(expectedHost: "api.example.com")
    expect(normalized.receive(clientHello("API.Example.COM."), offset: 0) == .serverName("api.example.com"), "canonical SNI match")
    var gap = TLSInspection(expectedHost: "api.example.com")
    expect(gap.receive(hello, offset: 1) == .deny("tls_unparsed"), "missing byte offset fails closed")
    var changedPrefix = TLSInspection(expectedHost: "api.example.com")
    _ = changedPrefix.receive(hello.prefix(5), offset: 0)
    var changed = hello; changed[2] = 3
    expect(changedPrefix.receive(changed, offset: 0) == .deny("tls_unparsed"), "peek prefix cannot be replaced")
    expect(TLSClientHello.inspect(clientHello("api.example.com", duplicateSNI: true)) == .deny("tls_unparsed"), "duplicate SNI rejected")
    let echExtension: [UInt8] = [0xfe, 0x0d, 0, 4, 0x42, 0x87, 0x19, 0xff]
    let echHello = clientHello("api.example.com", extra: echExtension)
    expect(TLSClientHello.inspect(echHello) == .serverName("api.example.com", echPresent: true), "ECH/GREASE presence is diagnostic, not a blanket deny")
    var matchingECH = TLSInspection(expectedHost: "api.example.com")
    expect(matchingECH.receive(echHello, offset: 0) == .serverName("api.example.com", echPresent: true), "ECH/GREASE with exact outer SNI allowed")
    var wrongECH = TLSInspection(expectedHost: "other.example.com")
    expect(wrongECH.receive(echHello, offset: 0) == .deny("sni_mismatch"), "ECH/GREASE cannot bypass exact outer-SNI gate")
    expect(matchingECH.echPresent && wrongECH.echPresent, "ECH evidence survives both allow and mismatch")
    expect(TLSClientHello.inspect(clientHello(nil, extra: echExtension)) == .deny("sni_missing"), "ECH/GREASE cannot substitute for missing SNI")
    expect(TLSClientHello.inspect(clientHello("api.example.com", extra: echExtension + echExtension)) == .deny("tls_unparsed"), "duplicate ECH still rejects malformed hello")
    var marked = domain
    marked.echPresent = matchingECH.echPresent
    let markedReceipt = Receipt.flow(flow(hostname: "api.example.com"), result: marked, hostnameMode: "os-metadata")
    expect(try markedReceipt.jsonLine().contains("ech_present;"), "ECH presence appears in bounded receipt detail")
    expect(try !Receipt.flow(flow(), result: domain, hostnameMode: "os-metadata").jsonLine().contains("ech_present"), "ordinary TLS receipts do not claim ECH")
    for name in ["", "evil\0.example.com", "éxample.com", "127.0.0.1", "bad..example.com"] {
        expect(TLSClientHello.inspect(clientHello(name)) == .deny("tls_unparsed"), "invalid SNI rejected")
    }
    expect(TLSClientHello.inspect(Data([0x16, 3, 1, 0x40, 0])) == .deny("tls_unparsed"), "oversized record rejected from header")
    expect(TLSClientHello.inspect(Data(repeating: 0x16, count: TLSClientHello.maximumBytes + 1)) == .deny("tls_unparsed"), "buffer cap enforced")
    var crossRecord = hello; crossRecord[8] += 1
    expect(TLSClientHello.inspect(crossRecord) == .deny("tls_unparsed"), "ClientHello split across TLS records rejected")
    var trailing = hello; trailing[hello.count - 1] = 0
    expect(TLSClientHello.inspect(trailing) == .deny("tls_unparsed"), "NUL in SNI cannot pass parser")

    let telemetry = FlowTelemetry()
    expect(!telemetry.shouldLog(AppEvaluator.evaluate(flow(resolution: .adHoc), configuration: config)), "ad hoc destinations not logged")
    expect(!telemetry.shouldLog(AppEvaluator.evaluate(flow(app: other), configuration: config)), "other app destinations not logged")
    expect(!telemetry.shouldLog(AppEvaluator.evaluate(flow(app: other), configuration: denyUnmatched)), "unmatched deny is count only")
    expect(telemetry.shouldLog(AppEvaluator.evaluate(flow(), configuration: config)), "bound app diagnostics kept")
    expect(telemetry.shouldLog(AppEvaluator.evaluate(flow(resolution: .invalidSignature), configuration: config)), "unknown-identity denial diagnosable")
    expect(telemetry.drain() == OutsideScopeCounts(allowed: 2, denied: 1), "outside-scope aggregate contains counts only")
    expect(telemetry.drain().isEmpty, "aggregate drains without retaining history")
}
