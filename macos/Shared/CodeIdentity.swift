import Darwin
import Foundation
import Security

/// Positive identities of running process images, keyed by the full audit
/// token. The token carries the PID version, which changes on exec, so one key
/// never names two images. Bounded; when full it starts over.
final class IdentityCache {
    private let lock = NSLock()
    private var entries: [Data: IdentityResolution] = [:]
    private let limit: Int

    init(limit: Int = 4096) { self.limit = limit }

    func read(_ token: Data) -> IdentityResolution? {
        lock.lock(); defer { lock.unlock() }
        return entries[token]
    }

    func store(_ token: Data, _ resolution: IdentityResolution) {
        lock.lock(); defer { lock.unlock() }
        if entries.count >= limit { entries.removeAll(keepingCapacity: true) }
        entries[token] = resolution
    }

    func remove(_ token: Data) {
        lock.lock(); defer { lock.unlock() }
        entries.removeValue(forKey: token)
    }

    var count: Int {
        lock.lock(); defer { lock.unlock() }
        return entries.count
    }
}

enum CodeIdentity {
    static let cache = IdentityCache()

    private static func requirement(_ text: String) -> SecRequirement? {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess else { return nil }
        return requirement
    }

    /// The audit token includes the process generation. No PID-only lookups,
    /// paths, claimed bundle IDs or parent scans.
    ///
    /// A verified or ad hoc result is kept for that process image. Full
    /// validation also checks the files on disk, so without the cache an app
    /// that updates itself while running (or whose bundle changes) would lose
    /// its identity until it restarts: denied even under unmatched=allow, and a
    /// bound app would stop matching its binding. A cached result is used only
    /// while the kernel still reports the running code as valid, so code that
    /// becomes invalid falls back to full validation and is denied.
    static func resolve(auditToken: Data?) -> IdentityResolution {
        guard let auditToken, auditToken.count == MemoryLayout<audit_token_t>.size else { return .unresolved }
        var code: SecCode?
        let attributes = [kSecGuestAttributeAudit as String: auditToken] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code else { return .unresolved }
        if let cached = cache.read(auditToken) {
            if runningCodeIsValid(code) { return cached }
            cache.remove(auditToken)
        }
        let result = resolution(of: code)
        switch result {
        case .verified, .adHoc: cache.store(auditToken, result)
        case .unresolved, .invalidSignature: break
        }
        return result
    }

    /// The kernel's dynamic status only: no signature or disk validation.
    static func runningCodeIsValid(_ code: SecCode) -> Bool {
        var information: CFDictionary?
        let dynamic = unsafeBitCast(code, to: SecStaticCode.self)
        guard SecCodeCopySigningInformation(dynamic, SecCSFlags(rawValue: kSecCSDynamicInformation), &information) == errSecSuccess,
              let info = information as? [String: Any],
              let status = info[kSecCodeInfoStatus as String] as? NSNumber else { return false }
        return status.uint32Value & SecCodeStatus.valid.rawValue != 0
    }

    static func resolution(of code: SecCode) -> IdentityResolution {
        let strict = SecCSFlags(rawValue: kSecCSStrictValidate)
        var information: CFDictionary?
        // Security's documented polymorphic C API accepts SecCode here despite
        // its SecStaticCode Swift signature. Keep the dynamic object: converting
        // with SecCodeCopyStaticCode would discard the runtime status flags.
        let dynamic = unsafeBitCast(code, to: SecStaticCode.self)
        guard SecCodeCopySigningInformation(dynamic, SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSDynamicInformation), &information) == errSecSuccess,
              let info = information as? [String: Any],
              let flags = info[kSecCodeInfoFlags as String] as? NSNumber,
              let status = info[kSecCodeInfoStatus as String] as? NSNumber,
              status.uint32Value & SecCodeStatus.valid.rawValue != 0 else { return .invalidSignature }
        // One SecCodeCheckValidity per path: each call already checks the
        // dynamic status, that the running code matches its signature and the
        // strict bundle structure. Invalidated signed code fails in that call
        // and never falls into unmatched.
        let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String
        if flags.uint32Value & SecCodeSignatureFlags.adhoc.rawValue != 0 {
            // Valid ad hoc signatures satisfy validity without an identity anchor.
            guard teamID == nil, SecCodeCheckValidity(code, strict, nil) == errSecSuccess else { return .invalidSignature }
            return .adHoc
        }
        guard let signingID = info[kSecCodeInfoIdentifier as String] as? String, validSigningID(signingID) else {
            return SecCodeCheckValidity(code, strict, nil) == errSecSuccess ? .unresolved : .invalidSignature
        }
        let expression: String
        if let teamID {
            guard validTeamID(teamID) else { return .invalidSignature }
            expression = "anchor apple generic and identifier \"\(signingID)\" and certificate leaf[subject.OU] = \"\(teamID)\""
        } else {
            // Only Apple platform code can be considered known without a Team ID.
            expression = "anchor apple and identifier \"\(signingID)\""
        }
        // Check the dynamic guest against the exact signed metadata, including
        // the certificate's OU. An ad hoc signature cannot satisfy either anchor.
        guard let exact = requirement(expression), SecCodeCheckValidity(code, strict, exact) == errSecSuccess else { return .invalidSignature }
        return .verified(SigningIdentity(signingID: signingID, teamID: teamID))
    }

    static func currentResolution() -> IdentityResolution {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return .unresolved }
        return resolution(of: code)
    }

    static func current() -> SigningIdentity? { currentResolution().verifiedIdentity }
}
