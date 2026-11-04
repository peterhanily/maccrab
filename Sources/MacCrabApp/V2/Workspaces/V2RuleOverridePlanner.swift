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
}
