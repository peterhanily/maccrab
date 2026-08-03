// RuleChannelPolicy.swift
// Single release gate shared by maccrabctl and the runtime rule engine.

/// The signed out-of-band rule channel remains disabled until the owner records
/// an offline key ceremony and custody decision, then explicitly approves a
/// future release that carries the rotated public trust anchor.
public enum RuleChannelPolicy {
    public static let productionEnabled = false
}
