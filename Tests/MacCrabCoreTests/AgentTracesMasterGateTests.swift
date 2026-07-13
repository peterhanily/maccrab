// AgentTracesMasterGateTests.swift
// Tests for v1.21.4 Phase-6 6A — the agent-traces master switch made
// config-reachable (so the shipped System Extension, which can't be handed
// MACCRAB_AGENT_TRACES, can turn the producer + receiver on via
// agent_traces_config.json) and its env-OR-config combine.

import Testing
import Foundation
import MacCrabCore

// MARK: - AgentTracesConfig: the new `enabled` master field

@Suite("AgentTracesConfig: master field decode + back-compat")
struct AgentTracesConfigMasterTests {

    @Test("default config has the master off (opt-in)")
    func defaultOff() {
        let cfg = AgentTracesConfig.defaultConfig
        #expect(cfg.enabled == false)
        #expect(cfg.receiverEnabled == false)
        #expect(cfg.port == 4318)
    }

    @Test("agent_traces_enabled decodes into the master field")
    func decodesMaster() throws {
        let json = """
        {"agent_traces_enabled": true, "receiverEnabled": true, "port": 4318}
        """.data(using: .utf8)!
        let cfg = try JSONDecoder().decode(AgentTracesConfig.self, from: json)
        #expect(cfg.enabled == true)
        #expect(cfg.receiverEnabled == true)
        #expect(cfg.port == 4318)
    }

    @Test("legacy file without the master key still decodes (enabled=false, other fields kept)")
    func legacyTolerantDecode() throws {
        // A file written before the `enabled` master existed.
        let json = """
        {"receiverEnabled": true, "port": 5555}
        """.data(using: .utf8)!
        let cfg = try JSONDecoder().decode(AgentTracesConfig.self, from: json)
        #expect(cfg.enabled == false)          // defaulted, not a decode failure
        #expect(cfg.receiverEnabled == true)   // preserved
        #expect(cfg.port == 5555)              // preserved
    }

    @Test("empty object decodes to all defaults (no partial-config wipe)")
    func emptyObjectDefaults() throws {
        let cfg = try JSONDecoder().decode(AgentTracesConfig.self, from: Data("{}".utf8))
        #expect(cfg.enabled == false)
        #expect(cfg.receiverEnabled == false)
        #expect(cfg.port == 4318)
    }

    @Test("write → read round-trips the master field")
    func roundTrip() {
        let dir = NSTemporaryDirectory() + "maccrab-agenttraces-test-\(UUID().uuidString)"
        let path = dir + "/agent_traces_config.json"
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let written = AgentTracesConfig(enabled: true, receiverEnabled: true, port: 4318)
        #expect(AgentTracesConfigStore.write(written, to: path) == true)

        let read = AgentTracesConfigStore.read(from: path)
        #expect(read?.enabled == true)
        #expect(read?.receiverEnabled == true)
        #expect(read == written)
    }

    @Test("loadEffective returns default (master off) when no config file is present")
    func loadEffectiveDefaultWhenAbsent() {
        // On a clean host (no /Library or /Users agent_traces_config.json)
        // the effective config is the opt-in default. This documents the
        // precedence fall-through: system → newest user home → default.
        let eff = AgentTracesConfigStore.loadEffective()
        // We can't guarantee the host has no file, so only assert the
        // invariant that matters when absent: the type resolves and the
        // master defaults off unless something explicitly enabled it.
        if AgentTracesConfigStore.read(from: AgentTracesConfigStore.systemPath) == nil,
           AgentTracesConfigStore.findUserHomeConfigPath() == nil {
            #expect(eff.enabled == false)
            #expect(eff == .defaultConfig)
        }
    }
}

// MARK: - ESCollector master gate: env OR config

@Suite("ESCollector: agent-traces master gate (env OR config)")
struct ESCollectorMasterGateTests {

    @Test("pure combine truth table — env OR config")
    func truthTable() {
        #expect(ESCollector.agentTracesMasterEnabled(env: false, config: false) == false)
        #expect(ESCollector.agentTracesMasterEnabled(env: true,  config: false) == true)  // env back-compat
        #expect(ESCollector.agentTracesMasterEnabled(env: false, config: true)  == true)  // config-reachable
        #expect(ESCollector.agentTracesMasterEnabled(env: true,  config: true)  == true)
    }

    @Test("applyConfigMaster(true) turns the gate on")
    func configMasterEnables() {
        // Post-condition only (the setter is monotonic + process-global,
        // seeded from env at type-load) so this is order-independent.
        ESCollector.applyConfigMaster(true)
        #expect(ESCollector.isAgentTracesEnabled == true)
    }

    @Test("applyConfigMaster(false) never turns an already-on gate off (monotonic)")
    func configMasterMonotonic() {
        ESCollector.applyConfigMaster(true)
        ESCollector.applyConfigMaster(false)
        #expect(ESCollector.isAgentTracesEnabled == true)
    }
}
