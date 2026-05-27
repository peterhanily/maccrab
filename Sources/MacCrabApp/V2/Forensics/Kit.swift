// Kit.swift — operator-facing scan bundle.
//
// A Kit is a curated set of scanners for a specific operator
// scenario (incident response, phishing triage, supply-chain
// audit, etc.). Operators don't pick individual scanners —
// they pick a kit shaped to a job.
//
// Schema matches maccrab.com/rave/schemas/kit.json (v0).
// JSON files ship bundled in MacCrab.app/Contents/Resources/kits/
// from rc.4. rc.7 fetches them from the rave catalog directly.

import Foundation

/// Operator-facing scan bundle.
public struct Kit: Identifiable, Hashable, Codable, Sendable {
    public let id: String
    public let name: String
    public let description: String
    public let version: String
    public let maintainer: String
    public let category: Category
    public let minMaccrabVersion: String
    public let plugins: [PluginRef]
    public let trustTier: TrustTier
    public let createdAt: String
    public let updatedAt: String
    /// Whether this kit needs an encrypted case. Required for any
    /// kit that includes a collector emitting content / personalComms
    /// artifacts (mail, imessage-*, facetime, safari-deep,
    /// applescript-runtime, etc.) — the store rejects those at
    /// INSERT into a plaintext case (Pass 2026-D).
    ///
    /// Defaults to false when the JSON omits the field (backwards
    /// compat with rc.4–rc.9 kits).
    public let encrypted: Bool

    public enum Category: String, Codable, Sendable, CaseIterable {
        case incidentResponse = "incident-response"
        case audit
        case posture
        case triage
        case monitoring
        case compliance
        case research

        /// Operator-facing label.
        public var displayName: String {
            switch self {
            case .incidentResponse: return "Incident response"
            case .audit:            return "Audit"
            case .posture:          return "Posture"
            case .triage:           return "Triage"
            case .monitoring:       return "Monitoring"
            case .compliance:       return "Compliance"
            case .research:         return "Research"
            }
        }

        /// SF Symbol — used in kit cards.
        public var sfSymbol: String {
            switch self {
            case .incidentResponse: return "exclamationmark.triangle.fill"
            case .audit:            return "checklist"
            case .posture:          return "shield.lefthalf.filled"
            case .triage:           return "envelope.open.fill"
            case .monitoring:       return "waveform.path.ecg"
            case .compliance:       return "doc.text.fill"
            case .research:         return "magnifyingglass.circle.fill"
            }
        }
    }

    public enum TrustTier: String, Codable, Sendable {
        case firstParty = "first-party"
        case verifiedCommunity = "verified-community"
        case unverified
    }

    public struct PluginRef: Hashable, Codable, Sendable {
        public let pluginID: String
        public let minVersion: String
        public let role: String
        public let required: Bool

        enum CodingKeys: String, CodingKey {
            case pluginID = "plugin_id"
            case minVersion = "min_version"
            case role
            case required
        }
    }

    enum CodingKeys: String, CodingKey {
        case id, name, description, version, maintainer, category, plugins, encrypted
        case minMaccrabVersion = "min_maccrab_version"
        case trustTier = "trust_tier"
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decode(String.self, forKey: .id)
        self.name = try c.decode(String.self, forKey: .name)
        self.description = try c.decode(String.self, forKey: .description)
        self.version = try c.decode(String.self, forKey: .version)
        self.maintainer = try c.decode(String.self, forKey: .maintainer)
        self.category = try c.decode(Category.self, forKey: .category)
        self.minMaccrabVersion = try c.decode(String.self, forKey: .minMaccrabVersion)
        self.plugins = try c.decode([PluginRef].self, forKey: .plugins)
        self.trustTier = try c.decode(TrustTier.self, forKey: .trustTier)
        self.createdAt = try c.decode(String.self, forKey: .createdAt)
        self.updatedAt = try c.decode(String.self, forKey: .updatedAt)
        self.encrypted = try c.decodeIfPresent(Bool.self, forKey: .encrypted) ?? false
    }
}

/// Loads kits from the app's bundled `kits/` resource directory
/// (rc.4). rc.7 swaps in a rave-backed loader that fetches +
/// caches catalog.json.
public enum KitLoader {
    /// Returns the kits bundled in MacCrab.app. The build
    /// pipeline flattens Resources/ into the SPM-built
    /// MacCrab_MacCrabApp.bundle, so kits live as
    /// `com.maccrab.kit.*.json` at the bundle root. Decode
    /// failures are logged + skipped.
    public static func loadBundledKits() -> [Kit] {
        // Search both the SPM resource bundle (Bundle.module
        // equivalent) and the .app's main bundle in case the
        // build pipeline differs across debug/release.
        let candidateBundles: [Bundle] = {
            var bs: [Bundle] = [Bundle.main]
            // Look for the SPM-generated MacCrab_MacCrabApp.bundle
            // nested inside Resources/.
            if let mainResURL = Bundle.main.resourceURL,
               let nested = Bundle(url: mainResURL.appendingPathComponent("MacCrab_MacCrabApp.bundle")) {
                bs.append(nested)
            }
            return bs
        }()

        var kits: [Kit] = []
        let decoder = JSONDecoder()
        let fm = FileManager.default
        for bundle in candidateBundles {
            guard let resURL = bundle.resourceURL else { continue }
            guard let entries = try? fm.contentsOfDirectory(
                at: resURL, includingPropertiesForKeys: nil
            ) else { continue }
            for entry in entries where entry.lastPathComponent.hasPrefix("com.maccrab.kit.") && entry.pathExtension == "json" {
                guard let data = try? Data(contentsOf: entry),
                      let kit = try? decoder.decode(Kit.self, from: data) else {
                    continue
                }
                if !kits.contains(where: { $0.id == kit.id }) {
                    kits.append(kit)
                }
            }
        }
        // Order: IR first (most common job), then category, then name.
        return kits.sorted { lhs, rhs in
            if lhs.category == .incidentResponse && rhs.category != .incidentResponse { return true }
            if rhs.category == .incidentResponse && lhs.category != .incidentResponse { return false }
            if lhs.category != rhs.category { return lhs.category.rawValue < rhs.category.rawValue }
            return lhs.name < rhs.name
        }
    }
}
