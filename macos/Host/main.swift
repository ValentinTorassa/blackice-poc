import Foundation
import NetworkExtension
import SystemExtensions
import os

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

func output(_ value: [String: Any]) {
    do {
        let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .prettyPrinted])
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([10]))
    } catch { fail("output_encoding_failed") }
}

func readBounded(_ path: String) throws -> Data {
    let file = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
    defer { try? file.close() }
    let data = try file.read(upToCount: StrictJSON.maximumBytes + 1) ?? Data()
    guard data.count <= StrictJSON.maximumBytes else { throw ConfigurationError.invalid("configuration_size") }
    return data
}

func requireSignedHost() {
    guard Bundle.main.bundleIdentifier == AppFilterConstants.hostBundleID,
          let identity = CodeIdentity.current(), identity.teamID != nil,
          identity.signingID == AppFilterConstants.hostBundleID else {
        fail("built, unsigned: activation and preference changes require the provisioned Developer ID host")
    }
}

func withOwnerPresence(_ action: HostAction, candidate: AppConfiguration? = nil,
                       perform: @escaping (NEFilterManager) -> Void) {
    requireSignedHost()
    let parent = AuthorizationParent.current()
    loadManager { manager in
        // Capture immutable preference values before prompting, then check that
        // the policy described to the user has not changed during authentication.
        let previousVendor = manager.providerConfiguration?.vendorConfiguration as NSDictionary?
        let previousEnabled = manager.isEnabled
        let previousExists = manager.providerConfiguration != nil
        let subject: AuthorizationPolicy
        if let candidate { subject = .available(candidate) }
        else if let data = previousVendor?[AppFilterConstants.configurationKey] as? Data,
                let config = try? AppConfiguration(data: data) { subject = .available(config) }
        else { subject = previousExists ? .unreadable : .absent }
        let prompt = AuthorizationPrompt(action: action, policy: subject, parent: parent)
        PresenceGate.perform(prompt, using: SystemPresenceAuthenticator(), announce: { reason in
            FileHandle.standardError.write(Data((reason + "\n").utf8))
        }, denied: {
            auditControl(action, parent: parent.pid, approved: false)
            fail("user_presence_required_or_cancelled")
        }, authorized: {
            DispatchQueue.main.async {
                loadManager { current in
                    guard previousVendor == (current.providerConfiguration?.vendorConfiguration as NSDictionary?),
                          previousEnabled == current.isEnabled,
                          previousExists == (current.providerConfiguration != nil) else {
                        fail("configuration_changed_during_authentication: review and retry")
                    }
                    auditControl(action, parent: parent.pid, approved: true)
                    perform(current)
                }
            }
        })
    }
}

func auditControl(_ action: HostAction, parent: pid_t, approved: Bool) {
    var receipt = Receipt(scope: "app-control", policy: "unavailable", generation: 0,
                          point: "control", event: "owner_authentication")
    receipt.verdict = approved ? "allow" : "deny"
    receipt.reason = approved ? "user_presence_confirmed" : "user_presence_refused"
    receipt.detail = "backend=network_extension;action=\(action.rawValue);parent_pid=\(parent)"
    let logger = Logger(subsystem: AppFilterConstants.logSubsystem, category: "control")
    if let line = try? receipt.jsonLine() { logger.notice("\(line, privacy: .public)") }
}

func loadManager(_ body: @escaping (NEFilterManager) -> Void) {
    let manager = NEFilterManager.shared()
    manager.loadFromPreferences { error in
        guard error == nil else { fail("filter_preferences_load_failed") }
        if let configuration = manager.providerConfiguration,
           configuration.filterDataProviderBundleIdentifier != AppFilterConstants.extensionBundleID {
            fail("foreign_filter_configuration: refusing to change it")
        }
        body(manager)
    }
}

final class ExtensionRequestDelegate: NSObject, OSSystemExtensionRequestDelegate {
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        output(["state": "awaiting_system_extension_approval", "enforcement_verified": false])
    }
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension candidate: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        existing.bundleIdentifier == AppFilterConstants.extensionBundleID &&
            candidate.bundleIdentifier == AppFilterConstants.extensionBundleID ? .replace : .cancel
    }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        output(["state": result == .completed ? "extension_request_completed" : "restart_required",
                "enforcement_verified": false])
        exit(result == .completed ? 0 : 2)
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let error = error as NSError
        fail("system_extension_request_failed: \(error.domain)/\(error.code)")
    }
}

let args = Array(CommandLine.arguments.dropFirst())
let usage = """
BlackiceApp (unsigned build and qualified deployment helper)
  status
  validate CONFIG.json
  make-config POLICY.json TEAM_ID SIGNING_ID app-SCOPE allow|deny ip-only|os-metadata
  activate
  enable CONFIG.json
  disable
  remove-config
  deactivate
The last five commands require Developer ID signing, entitlements and fresh user authentication.
enable updates an existing configuration in place with a strictly higher generation.
An enabled preference is not a verified enforcement status.
"""

let delegate = ExtensionRequestDelegate()
guard let command = args.first else { print(usage); exit(0) }
do {
    switch command {
    case "status" where args.count == 1:
        let signed = CodeIdentity.current() != nil
        var status: [String: Any] = [
            "state": signed ? "built, signed; runtime unverified" : "built, unsigned",
            "enforcement_verified": false, "durable_receipts": false,
            "scope_kind": "app", "existing_flows": "not_revoked",
            "required_identity": "audit_token_and_validated_code_signature",
            "hostname_modes": ["ip-only", "os-metadata"],
            "process_tree_containment": false
        ]
        if signed {
            loadManager { manager in
                status["preferences_enabled"] = manager.isEnabled
                output(status); exit(0)
            }
        } else { output(status); exit(0) }
    case "validate" where args.count == 2:
        let config = try AppConfiguration(data: readBounded(args[1]))
        output(["valid": true, "configuration": config.id, "generation": config.generation,
                "apps": config.apps.count, "hostname_mode": config.hostnameMode, "enforcement_verified": false])
        exit(0)
    case "make-config" where args.count == 7:
        let data = try readBounded(args[1])
        _ = try NetworkPolicy(data: data)
        guard let policy = String(data: data, encoding: .utf8) else { fail("policy_requires_utf8") }
        let doc = AppConfigurationDocument(generation: 1, unmatched: args[5], hostnameMode: args[6],
            apps: [AppBindingDocument(scope: args[4], teamID: args[2], signingID: args[3], policyJSON: policy)])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
        let encoded = try encoder.encode(doc)
        _ = try AppConfiguration(data: encoded)
        FileHandle.standardOutput.write(encoded)
        FileHandle.standardOutput.write(Data([10]))
        exit(0)
    case "activate" where args.count == 1:
        withOwnerPresence(.activate) { _ in
            let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: AppFilterConstants.extensionBundleID,
                                                                    queue: .main)
            request.delegate = delegate
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    case "enable" where args.count == 2:
        let data = try readBounded(args[1])
        let candidate = try AppConfiguration(data: data)
        withOwnerPresence(.enable, candidate: candidate) { manager in
            do {
                var current: AppConfiguration?
                if let existing = manager.providerConfiguration {
                    guard let saved = existing.vendorConfiguration?[AppFilterConstants.configurationKey] as? Data else {
                        fail("invalid_saved_configuration")
                    }
                    current = try AppConfiguration(data: saved)
                }
                try ConfigurationUpdate.validate(candidate, replacing: current)
            } catch { fail("update_requires_valid_higher_generation") }
            let provider = NEFilterProviderConfiguration()
            provider.filterSockets = true
            provider.filterPackets = false
            provider.filterDataProviderBundleIdentifier = AppFilterConstants.extensionBundleID
            provider.vendorConfiguration = [AppFilterConstants.configurationKey: data]
            manager.providerConfiguration = provider
            manager.localizedDescription = "blackice app filter"
            manager.isEnabled = true
            manager.saveToPreferences { error in
                guard error == nil else { fail("filter_preferences_save_failed") }
                output(["state": "preferences_saved", "enforcement_verified": false,
                        "generation": candidate.generation, "existing_flows": "not_revoked",
                        "next": "verify provider acknowledgement and real new-flow enforcement"])
                exit(0)
            }
        }
    case "disable" where args.count == 1:
        withOwnerPresence(.disable) { manager in
            guard manager.providerConfiguration != nil else { fail("no_owned_configuration") }
            manager.isEnabled = false
            manager.saveToPreferences { error in
                guard error == nil else { fail("filter_disable_failed") }
                output(["state": "disabled_preferences_saved", "enforcement_verified": false]); exit(0)
            }
        }
    case "remove-config" where args.count == 1:
        withOwnerPresence(.removeConfiguration) { manager in
            guard !manager.isEnabled else { fail("disable_before_removal") }
            guard manager.providerConfiguration != nil else { fail("no_owned_configuration") }
            manager.removeFromPreferences { error in
                guard error == nil else { fail("filter_remove_failed") }
                output(["state": "owned_configuration_removed", "enforcement_verified": false]); exit(0)
            }
        }
    case "deactivate" where args.count == 1:
        withOwnerPresence(.deactivate) { manager in
            guard !manager.isEnabled else { fail("disable_before_deactivation") }
            let request = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: AppFilterConstants.extensionBundleID,
                                                                      queue: .main)
            request.delegate = delegate
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    default: fail(usage)
    }
} catch let error as ConfigurationError { fail(error.description) }
catch { fail("invalid_configuration_or_file_read_failed") }

DispatchQueue.main.asyncAfter(deadline: .now() + 120) {
    fail("request_timeout: outcome unverified; inspect System Settings before retrying")
}
RunLoop.main.run()
