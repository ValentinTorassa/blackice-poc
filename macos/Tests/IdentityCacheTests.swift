import Darwin
import Foundation

private func ownAuditToken() -> Data? {
    var token = audit_token_t()
    var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
    let result = withUnsafeMutablePointer(to: &token) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
        }
    }
    guard result == KERN_SUCCESS else { return nil }
    return withUnsafeBytes(of: &token) { Data($0) }
}

/// Replaces this test executable on disk while it runs, as an in-place app
/// update does: a new file renamed over the path leaves the running image with
/// no name on disk. A hard link would keep that name, and Security would still
/// find the original file. Puts a copy back afterwards.
private func withExecutableReplaced(_ body: () throws -> Void) throws {
    guard let path = Bundle.main.executablePath else { expect(false, "test executable path known"); return }
    let original = path + ".original", replacement = path + ".replacement"
    unlink(original); unlink(replacement)
    try FileManager.default.copyItem(atPath: path, toPath: original)
    try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: replacement)
    expect(rename(replacement, path) == 0, "test executable replaced on disk")
    defer { _ = rename(original, path) }
    try body()
}

func identityCacheRegressions() throws {
    let small = IdentityCache(limit: 2)
    for byte in UInt8(1)...3 { small.store(Data([byte]), .adHoc) }
    expect(small.count <= 2, "identity cache stays bounded")

    guard let token = ownAuditToken() else { expect(false, "own audit token available"); return }
    CodeIdentity.cache.remove(token)
    expect(CodeIdentity.resolve(auditToken: token) == .adHoc, "own process resolves by audit token")
    expect(CodeIdentity.cache.read(token) == .adHoc, "verified or ad hoc identity kept for the process image")

    try withExecutableReplaced {
        // Full validation depends on the files on disk: an updated app loses it.
        expect(CodeIdentity.currentResolution() == .invalidSignature, "full validation fails once the executable changes on disk")
        // The running image is still the one the kernel validated.
        expect(CodeIdentity.resolve(auditToken: token) == .adHoc, "running app keeps its identity after an in-place update")
        CodeIdentity.cache.remove(token)
        expect(CodeIdentity.resolve(auditToken: token) == .invalidSignature, "without a cached identity the changed app still fails closed")
        expect(CodeIdentity.cache.read(token) == nil, "failed identities are not cached")
    }
    expect(CodeIdentity.currentResolution() == .adHoc, "test executable restored on disk")
}
