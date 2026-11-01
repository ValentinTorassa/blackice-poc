import Darwin
import Foundation
import Network
import NetworkExtension
import os

/// Provider is instantiated by NetworkExtension using the Info.plist class map.
final class FilterDataProvider: NEFilterDataProvider {
    private let snapshots = SnapshotStore()
    private let lifecycle = DispatchQueue(label: "com.valentorassa.blackice.filter.lifecycle")
    private var runID: UUID?
    private var observation: NSKeyValueObservation?
    private var timer: DispatchSourceTimer?
    private var nextSummary: TimeInterval = 0
    private let telemetry = FlowTelemetry()
    private let pendingLock = NSLock()
    private var pending: [UUID: PendingTLS] = [:]
    private let logger = Logger(subsystem: AppFilterConstants.logSubsystem, category: "receipts")

    private struct PendingTLS {
        let flow: NEFilterSocketFlow
        let facts: FlowFacts
        let result: AppDecision
        let deadline: TimeInterval
        var inspection: TLSInspection
    }

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let identifier = UUID()
        do {
            let candidate = try readConfiguration()
            try lifecycle.sync {
                observation = nil
                timer?.cancel(); timer = nil
                snapshots.clear()
                runID = identifier
                try snapshots.install(candidate)
            }
            apply(Self.makeSettings()) { [weak self] error in
                guard let self else { completionHandler(ConfigurationError.invalid("provider_stopped")); return }
                self.lifecycle.async { [self] in
                    guard self.runID == identifier else {
                        completionHandler(ConfigurationError.invalid("provider_stopped")); return
                    }
                    if let error {
                        self.runID = nil
                        self.snapshots.clear()
                        self.controlEvent("warning", reason: "filter_settings_failed")
                        completionHandler(error)
                        return
                    }
                    self.observation = self.observe(\.filterConfiguration, options: [.new]) { [weak self] _, _ in
                        guard let self else { return }
                        self.lifecycle.async {
                            guard self.runID == identifier else { return }
                            self.reloadConfiguration()
                        }
                    }
                    // Also catches a preference change while applySettings was pending.
                    self.reloadConfiguration()
                    self.startMaintenance()
                    self.controlEvent("scope_start", reason: "filter_settings_applied")
                    completionHandler(nil)
                }
            }
        } catch {
            snapshots.clear()
            controlEvent("warning", reason: "invalid_start_configuration")
            completionHandler(ConfigurationError.invalid("invalid_start_configuration"))
        }
    }

    static func makeSettings() -> NEFilterSettings {
        // Default rules exclude loopback. Explicit capture is essential for
        // local-proxy policy; no network settings are applied by this factory.
        let loopback = [("127.0.0.1", 8), ("::1", 128), ("::ffff:127.0.0.1", 104)]
        let rules = loopback.map { address, prefix in
            NEFilterRule(networkRule: NENetworkRule(
                destinationNetwork: NWHostEndpoint(hostname: address, port: "0"),
                prefix: prefix, protocol: .any), action: .filterData)
        }
        return NEFilterSettings(rules: rules, defaultAction: .filterData)
    }

    private func readConfiguration() throws -> AppConfiguration {
        guard let values = filterConfiguration.vendorConfiguration,
              Set(values.keys) == [AppFilterConstants.configurationKey],
              let data = values[AppFilterConstants.configurationKey] as? Data else {
            throw ConfigurationError.invalid("missing_app_configuration")
        }
        return try AppConfiguration(data: data)
    }

    private func reloadConfiguration() {
        do {
            let previous = snapshots.read()?.generation
            try snapshots.install(readConfiguration())
            if previous != snapshots.read()?.generation {
                discardPending(reason: "policy_changed") { _ in true }
            }
            controlEvent("policy_activated", reason: "snapshot_installed")
        } catch {
            // Invalid or stale updates cannot replace a working snapshot.
            controlEvent("warning", reason: "configuration_update_rejected")
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lifecycle.async {
            self.runID = nil
            self.observation = nil
            self.timer?.cancel(); self.timer = nil
            self.discardPending(reason: "provider_stopped") { _ in true }
            self.emitOutsideScopeCounts()
            self.controlEvent("scope_end", reason: "filter_stopped")
            self.snapshots.clear()
            completionHandler()
        }
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        let configuration = snapshots.read()
        let socket = flow as? NEFilterSocketFlow
        let endpoint = socket?.remoteEndpoint as? NWHostEndpoint
        // A numeric endpoint is required: remoteHostname does not supply an IP.
        let ip = endpoint.flatMap { IPAddress($0.hostname) }
        let port = endpoint.flatMap { UInt16($0.port) }
        let tcp = socket?.socketType == SOCK_STREAM && socket?.socketProtocol == IPPROTO_TCP
        let udp = socket?.socketType == SOCK_DGRAM && socket?.socketProtocol == IPPROTO_UDP
        let internet = socket?.socketFamily == AF_INET || socket?.socketFamily == AF_INET6
        let direction: FlowFacts.Direction = flow.direction == .outbound ? .outbound :
            (flow.direction == .inbound ? .inbound : .unknown)
        let app = CodeIdentity.resolve(auditToken: flow.sourceAppAuditToken)
        let process = flow.sourceProcessAuditToken == flow.sourceAppAuditToken ? app :
            CodeIdentity.resolve(auditToken: flow.sourceProcessAuditToken)
        let facts = FlowFacts(direction: direction, app: app, process: process,
                              supportedSocket: internet && (tcp || udp), isTCP: tcp,
                              hostname: socket?.remoteHostname, ip: ip, port: port)
        let result = AppEvaluator.evaluate(facts, configuration: configuration)
        if let host = result.requiredTLSHost, let socket {
            pendingLock.lock()
            // 256 * 16 KiB transient peek data at most, plus fixed metadata.
            guard pending.count < 256, pending[flow.identifier] == nil else {
                pendingLock.unlock()
                emitFlow(facts, result: resolved(result, denied: "tls_capacity"))
                return .drop()
            }
            pending[flow.identifier] = PendingTLS(flow: socket, facts: facts, result: result,
                deadline: ProcessInfo.processInfo.systemUptime + 10,
                inspection: TLSInspection(expectedHost: host))
            pendingLock.unlock()
            // Request the header first. Every later peek keeps passBytes at zero.
            // No allow receipt is emitted until the complete ClientHello matches.
            return .filterDataVerdict(withFilterInbound: false, peekInboundBytes: 0,
                                      filterOutbound: true, peekOutboundBytes: 5)
        }
        emitFlow(facts, result: result)
        return result.decision.allowed ? .allow() : .drop()
    }

    override func handleOutboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int,
                                     readBytes: Data) -> NEFilterDataVerdict {
        pendingLock.lock(); defer { pendingLock.unlock() }
        guard var entry = pending[flow.identifier] else { return .drop() }
        let outcome: TLSHelloResult
        if snapshots.read()?.generation != entry.result.generation { outcome = .deny("policy_changed") }
        else if ProcessInfo.processInfo.systemUptime >= entry.deadline { outcome = .deny("tls_timeout") }
        else { outcome = entry.inspection.receive(readBytes, offset: offset) }
        switch outcome {
        case .needMore(let total):
            pending[flow.identifier] = entry
            return .init(passBytes: 0, peekBytes: total)
        case .serverName:
            pending.removeValue(forKey: flow.identifier)
            emitFlow(entry.facts, result: resolved(entry.result, denied: nil, echPresent: entry.inspection.echPresent))
            return .allow()
        case .deny(let reason):
            pending.removeValue(forKey: flow.identifier)
            emitFlow(entry.facts, result: resolved(entry.result, denied: reason, echPresent: entry.inspection.echPresent))
            return .drop()
        }
    }

    override func handleOutboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        pendingLock.lock()
        let entry = pending.removeValue(forKey: flow.identifier)
        pendingLock.unlock()
        if let entry { emitFlow(entry.facts, result: resolved(entry.result, denied: "tls_unparsed")) }
        return .drop()
    }

    private func resolved(_ result: AppDecision, denied reason: String?, echPresent: Bool = false) -> AppDecision {
        AppDecision(scope: result.scope, policy: result.policy, generation: result.generation,
                    decision: reason.map { Decision(allowed: false, reason: $0) } ?? result.decision,
                    echPresent: echPresent)
    }

    private func startMaintenance() {
        nextSummary = ProcessInfo.processInfo.systemUptime + 60
        let timer = DispatchSource.makeTimerSource(queue: lifecycle)
        timer.schedule(deadline: .now() + 1, repeating: 1)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            let now = ProcessInfo.processInfo.systemUptime
            self.discardPending(reason: "tls_timeout") { $0.deadline <= now }
            if now >= self.nextSummary { self.emitOutsideScopeCounts(); self.nextSummary = now + 60 }
        }
        self.timer = timer
        timer.resume()
    }

    /// Called outside flow callbacks, where NetworkExtension permits update().
    private func discardPending(reason: String, matching predicate: (PendingTLS) -> Bool) {
        pendingLock.lock()
        let removed = pending.filter { predicate($0.value) }
        for id in removed.keys { pending.removeValue(forKey: id) }
        pendingLock.unlock()
        for entry in removed.values {
            update(entry.flow, using: .drop(), for: .outbound)
            emitFlow(entry.facts, result: resolved(entry.result, denied: reason))
        }
    }

    private func emitOutsideScopeCounts() {
        let counts = telemetry.drain()
        guard !counts.isEmpty else { return }
        controlEvent("outside_scope_summary", reason: "aggregate_only",
                     detail: ";allowed=\(counts.allowed);denied=\(counts.denied)")
    }

    private func emitFlow(_ facts: FlowFacts, result: AppDecision) {
        guard telemetry.shouldLog(result) else { return }
        emit(Receipt.flow(facts, result: result, hostnameMode: snapshots.read()?.hostnameMode), privateFields: true)
    }

    private func controlEvent(_ event: String, reason: String, detail: String = "") {
        let config = snapshots.read()
        var receipt = Receipt(scope: "app-provider", policy: config?.id ?? "unavailable",
                              generation: config?.generation ?? 0, point: "control", event: event)
        receipt.reason = reason
        receipt.detail = "backend=network_extension;scope_kind=app;durable_receipts=unavailable" + detail
        emit(receipt)
    }

    private func emit(_ receipt: Receipt, privateFields: Bool = false) {
        do {
            let line = try receipt.jsonLine()
            // Diagnostic transport only: no concurrent writes to Zig scope files.
            // Unified logging can drop/truncate records. It is NOT a durable ledger.
            if privateFields { logger.notice("\(line, privacy: .private)") }
            else { logger.notice("\(line, privacy: .public)") }
        } catch {
            logger.error("receipt_encoding_failed;durable_receipts=unavailable")
        }
    }
}
