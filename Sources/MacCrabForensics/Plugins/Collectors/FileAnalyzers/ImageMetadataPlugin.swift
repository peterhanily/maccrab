// ImageMetadataPlugin — com.maccrab.forensics.image-metadata.
//
// Plan §13.7. Operator-supplied image file. Extracts EXIF / IPTC
// / XMP metadata via ImageIO. Risk surface: tracking pixels in
// downloaded images, GPS-tagged screenshots, document leakage
// via embedded thumbnail.

import Foundation
import ImageIO
import CryptoKit

public struct ImageMetadataPlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.image-metadata",
        version: "1.0.0",
        displayName: "Image Metadata",
        description: "Extracts EXIF / IPTC / XMP / TIFF metadata from an image file via ImageIO. Metadata class. Operator-supplied path.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [],
        inputs: [],
        outputs: [
            OutputSpec(contentType: "image.metadata", privacyClass: .metadata),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "image_metadata_path",
                description: "Extract EXIF / GPS / IPTC / XMP metadata from an image file.",
                exposesPrivacyClass: .metadata
            ),
        ],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    public func collect(case caseContext: CaseContext, window: TimeWindow?, output: any CollectorOutput) async throws -> CollectionResult {
        // Default sample target: macOS provides a stock asset.
        // Operator-supplied path lands when PluginRunner threads
        // inputs.
        let defaults = [
            "/System/Library/PrivateFrameworks/DesktopServicesPriv.framework/Versions/A/Resources/AppleScript Editor Document.icns",
            "/System/Library/CoreServices/DefaultDesktop.heic",
            "/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.icns",
        ].filter { FileManager.default.fileExists(atPath: $0) }
        var committed = 0
        var rejected = 0
        let now = Date()
        for path in defaults {
            guard let src = CGImageSourceCreateWithURL(URL(fileURLWithPath: path) as CFURL, nil) else { continue }
            guard let props = CGImageSourceCopyPropertiesAtIndex(src, 0, nil) as? [String: Any] else { continue }
            let width = (props[kCGImagePropertyPixelWidth as String] as? Int) ?? 0
            let height = (props[kCGImagePropertyPixelHeight as String] as? Int) ?? 0
            let dpi = (props[kCGImagePropertyDPIWidth as String] as? Double) ?? 0
            let colorModel = props[kCGImagePropertyColorModel as String] as? String ?? ""
            let hasGPS = props[kCGImagePropertyGPSDictionary as String] != nil
            let hasEXIF = props[kCGImagePropertyExifDictionary as String] != nil
            let hasXMP = props[kCGImagePropertyIPTCDictionary as String] != nil

            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { continue }
            let sha = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            let recordData: [String: JSONValue] = [
                "path": .string(path),
                "width": .integer(Int64(width)),
                "height": .integer(Int64(height)),
                "dpi": .double(dpi),
                "color_model": .string(colorModel),
                "has_gps": .bool(hasGPS),
                "has_exif": .bool(hasEXIF),
                "has_iptc": .bool(hasXMP),
            ]
            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "image.metadata",
                sourcePath: path,
                sha256: sha,
                observedAt: now,
                capturedAt: now,
                summary: "Image \(path): \(width)x\(height) \(colorModel)\(hasGPS ? " 📍" : "")",
                sizeBytes: Int64(data.count),
                confidence: .observed,
                privacyClass: .metadata,
                actor: NSUserName(),
                data: recordData
            )
            do { try await output.commit(record); committed += 1 } catch { rejected += 1 }
        }
        return CollectionResult(artifactsCommitted: committed, artifactsRejected: rejected, notes: ["image metadata: \(committed) images analyzed"], status: .ok)
    }
}
