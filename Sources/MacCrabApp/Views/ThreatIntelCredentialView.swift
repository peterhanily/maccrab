import SwiftUI
import MacCrabCore

/// Explicit credential operations, kept separate from enrichment consent.
/// The editor never preloads a secret into visible or persisted app state.
struct ThreatIntelCredentialState {
    enum Outcome: Equatable { case checked, saved, deleted, failed }
    private(set) var hasStoredKey: Bool?
    private(set) var outcome: Outcome = .checked

    mutating func refresh(read: () throws -> String?) {
        do { hasStoredKey = try read() != nil; outcome = .checked }
        catch { hasStoredKey = nil; outcome = .failed }
    }

    mutating func change(candidate: String?, write: (String?) throws -> Void,
                         read: () throws -> String?) {
        guard candidate != "", candidate != nil || hasStoredKey == true else {
            outcome = .failed
            return
        }
        do {
            try write(candidate)
            let stored = try read()
            guard stored == candidate else { hasStoredKey = nil; outcome = .failed; return }
            hasStoredKey = stored != nil
            outcome = candidate == nil ? .deleted : .saved
        } catch { hasStoredKey = nil; outcome = .failed }
    }
}

struct ThreatIntelCredentialView: View {
    @State private var candidate = ""
    @State private var credential = ThreatIntelCredentialState()
    private let secrets = SecretsStore()

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(String(localized: "settings.abuseCH.title", defaultValue: "abuse.ch Auth-Key"))
                .font(.subheadline).fontWeight(.medium)
            Text(String(localized: "settings.abuseCH.detail", defaultValue: "URLhaus and MalwareBazaar require an abuse.ch Auth-Key. Store it in the shared MacCrab Keychain group for the detection engine. Saving a key does not enable network enrichment or contact abuse.ch."))
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            SecureField(String(localized: "settings.abuseCH.newKey", defaultValue: "Enter a new Auth-Key"), text: $candidate)
                .textFieldStyle(.roundedBorder)
            HStack {
                Button(String(localized: "settings.abuseCH.save", defaultValue: "Save key")) { change(candidate) }
                    .disabled(candidate.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                Button(String(localized: "settings.abuseCH.delete", defaultValue: "Delete stored key"), role: .destructive) { change(nil) }
                    .disabled(credential.hasStoredKey != true)
                Button(String(localized: "common.refresh", defaultValue: "Refresh")) { refresh() }
            }
            Text(status)
                .font(.caption)
                .foregroundStyle(credential.outcome == .failed ? Color.orange : Color.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 8)
        .onAppear { refresh() }
        .onDisappear { candidate = "" }
    }

    private var status: String {
        switch credential.outcome {
        case .saved: return String(localized: "settings.abuseCH.saved", defaultValue: "Keychain save verified. The engine will read the key on its next enabled feed refresh; service acceptance has not been tested.")
        case .deleted: return String(localized: "settings.abuseCH.deleted", defaultValue: "Keychain deletion verified. An engine configured with a legacy environment key may still use that key.")
        case .failed: return String(localized: "settings.abuseCH.failed", defaultValue: "The Keychain operation could not be verified. Check Keychain access and refresh before retrying. Network settings were not changed.")
        case .checked:
            return credential.hasStoredKey == true
                ? String(localized: "settings.abuseCH.present", defaultValue: "A stored key is readable. Service acceptance has not been tested.")
                : String(localized: "settings.abuseCH.absent", defaultValue: "No shared Keychain key is stored. Feodo’s public feed does not require one.")
        }
    }

    private func refresh() {
        credential.refresh { try secrets.get(.abuseCHAuthKey) }
    }

    private func change(_ value: String?) {
        credential.change(candidate: value, write: { next in
            if let next { try secrets.set(.abuseCHAuthKey, value: next) }
            else { try secrets.delete(.abuseCHAuthKey) }
        }, read: { try secrets.get(.abuseCHAuthKey) })
        candidate = ""
    }
}
