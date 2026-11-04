import Foundation

/// Pure decisions behind the Detection workspace's user_rules override
/// writes, kept out of the view so tests can check them.
enum V2RuleOverridePlanner {
    /// Whether a severity change writes the override with "enabled": false.
    /// The engine never applies the rule profile to a user_rules file it
    /// loads, so when user_rules/<id>.json exists its own "enabled" decides.
    /// Otherwise the bundled rule's state as the dashboard shows it decides;
    /// for a bundled rule that state applies the profile, as the engine does.
    static func severityChangeKeepsDisabled(override: [String: Any]?, displayedEnabled: Bool) -> Bool {
        if let override { return (override["enabled"] as? Bool) == false }
        return !displayedEnabled
    }

    /// The override Enable installs, or nil when Enable removes the file.
    /// The remove-rule handler deletes user_rules/<id>.yml with the JSON, so
    /// Enable removes the override only when it is a pure disable copy of a
    /// bundled rule: a bundled rule with the id exists, no <id>.yml exists,
    /// and the two are equal apart from "enabled". Any other override (a rule
    /// the user made, an Edit YAML or a severity change) is returned with
    /// "enabled": true and every other field as it was.
    static func enabledOverride(_ override: [String: Any], bundled: [String: Any]?,
                                hasSourceYAML: Bool) -> [String: Any]? {
        if let bundled, !hasSourceYAML, equalApartFromEnabled(override, bundled) { return nil }
        var enabled = override
        enabled["enabled"] = true
        return enabled
    }

    /// The override a severity revert installs, or nil when the revert
    /// removes the file. The revert sets "level" back to the bundled rule's
    /// and keeps every other field, with "enabled": false while the rule stays
    /// disabled. It removes the file only when the rule does not stay
    /// disabled, no <id>.yml exists, and the result equals the bundled rule
    /// apart from "enabled".
    static func severityRevertedOverride(_ rule: [String: Any], bundled: [String: Any],
                                         hasSourceYAML: Bool, keepsDisabled: Bool) -> [String: Any]? {
        var reverted = rule
        reverted["level"] = bundled["level"]
        if !keepsDisabled, !hasSourceYAML, equalApartFromEnabled(reverted, bundled) { return nil }
        if keepsDisabled { reverted["enabled"] = false }
        return reverted
    }

    /// Compares the parsed JSON objects, so key order and formatting do not
    /// count: Disable writes its copy with sorted keys and pretty-printed,
    /// unlike the compiler's output.
    private static func equalApartFromEnabled(_ lhs: [String: Any], _ rhs: [String: Any]) -> Bool {
        var lhs = lhs, rhs = rhs
        lhs.removeValue(forKey: "enabled")
        rhs.removeValue(forKey: "enabled")
        return NSDictionary(dictionary: lhs).isEqual(to: rhs)
    }
}
