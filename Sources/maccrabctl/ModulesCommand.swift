// ModulesCommand.swift
// maccrabctl
//
// `maccrabctl modules` — surface each subsystem's documented maturity
// (stable / experimental / opt-in) at point of use. Before this, the
// ModuleStatus.catalog model existed and docs claimed a CLI + About-panel
// surface, but nothing actually consumed it (dead catalog). This is the CLI
// half of that promise.

import Foundation
import MacCrabCore

func printModules() {
    let catalog = ModuleStatus.catalog

    func badge(_ m: ModuleMaturity) -> String {
        switch m {
        case .stable:       return ANSIColor.wrap("[STABLE]      ", .blue)
        case .experimental: return ANSIColor.wrap("[EXPERIMENTAL]", .orange)
        case .optIn:        return ANSIColor.wrap("[OPT-IN]      ", .gray)
        }
    }

    let stable = catalog.filter { $0.maturity == .stable }.count
    let exp = catalog.filter { $0.maturity == .experimental }.count
    let opt = catalog.filter { $0.maturity == .optIn }.count
    print(ANSIColor.wrap("MacCrab modules — \(catalog.count) subsystems "
        + "(\(stable) stable, \(exp) experimental, \(opt) opt-in)", .bold))
    print("")

    for maturity in [ModuleMaturity.stable, .experimental, .optIn] {
        for m in catalog where m.maturity == maturity {
            print("  \(badge(m.maturity)) \(m.name) \(ANSIColor.wrap("(\(m.category))", .gray))")
            print("                 \(m.summary)")
        }
    }
    print("")
    print(ANSIColor.wrap("  experimental = functional but iterating; treat output as advisory.", .gray))
    print(ANSIColor.wrap("  opt-in       = disabled by default; enable via daemon_config / env var.", .gray))
}
