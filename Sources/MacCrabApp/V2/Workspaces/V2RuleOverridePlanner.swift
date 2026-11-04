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
    /// an override with a .yml beside it, or one whose id no bundled rule has
    /// (a rule the user made), is returned with "enabled": true and every
    /// other field as it was.
    ///
    /// Any other override is a JSON-only override of a bundled rule. Its
    /// writers (the Detection workspace's Disable, Enable and severity
    /// writes, and `maccrabctl rule severity`) copy the bundled rule or the
    /// existing override and change only "enabled" and "level", and the copy
    /// may be of an earlier version of the bundled rule. So Enable keeps only
    /// the override's level: when its "level" is a string other than the
    /// bundled rule's, the current bundled rule is returned with that level
    /// and "enabled": true, and otherwise nil.
    static func enabledOverride(_ override: [String: Any], bundled: [String: Any]?,
                                hasSourceYAML: Bool) -> [String: Any]? {
        guard let bundled, !hasSourceYAML else {
            var enabled = override
            enabled["enabled"] = true
            return enabled
        }
        guard let level = override["level"] as? String, level != (bundled["level"] as? String) else { return nil }
        var current = bundled
        current["level"] = level
        current["enabled"] = true
        return current
    }

    /// The override a severity revert installs, or nil when the revert
    /// removes the file. With a .yml beside the override, the revert sets
    /// "level" back to the bundled rule's and keeps every other field, with
    /// "enabled": false while the rule stays disabled. Without one, only the
    /// override's "enabled" and "level" can be the user's (see
    /// enabledOverride), so the revert removes the file, or returns the
    /// current bundled rule with "enabled": false while the rule stays
    /// disabled.
    static func severityRevertedOverride(_ rule: [String: Any], bundled: [String: Any],
                                         hasSourceYAML: Bool, keepsDisabled: Bool) -> [String: Any]? {
        guard hasSourceYAML else {
            guard keepsDisabled else { return nil }
            var current = bundled
            current["enabled"] = false
            return current
        }
        var reverted = rule
        reverted["level"] = bundled["level"]
        if keepsDisabled { reverted["enabled"] = false }
        return reverted
    }
}
