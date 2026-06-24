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
        description: "Extracts EXIF / IPTC / XMP / TIFF metadata + GPS coordinates + camera make/model from images in ~/Downloads (or an operator-supplied path) via ImageIO — surfaces location-tagged or camera-fingerprinted images. Metadata class.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [],
        inputs: [],
        outputs: [
            OutputSpec(
                contentType: "image.metadata",
                privacyClass: .metadata,
                viewerHint: ViewerHint(
                    viewer: .keyvalue,
                    fieldRoles: [
                        "observed_at": .timestamp,
                        "path": .path,
                        "width": .count,
                        "height": .count,
                        "dpi": .count,
                    ]
                )
            ),
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

    private static let imageExtensions: Set<String> =
        ["jpg", "jpeg", "png", "heic", "heif", "tiff", "tif", "gif", "webp", "dng", "cr2", "nef"]

    public func collect(case caseContext: CaseContext, window: TimeWindow?, output: any CollectorOutput) async throws -> CollectionResult {
        // Operator-supplied path wins; otherwise scan ~/Downloads for real images
        // (the sibling DocumentAnalyzerPlugin proves this path). No /System dogfood.
        var targets: [URL] = []
        if case .string(let p)? = caseContext.inputs.values["path"], !p.isEmpty {
            targets = [URL(fileURLWithPath: p)]
        } else {
            let downloads = URL(fileURLWithPath: NSHomeDirectory() + "/Downloads")
            if let urls = try? FileManager.default.contentsOfDirectory(
                at: downloads, includingPropertiesForKeys: [.fileSizeKey], options: [.skipsHiddenFiles]) {
                targets = urls.filter { Self.imageExtensions.contains($0.pathExtension.lowercased()) }
            }
        }
        if targets.isEmpty {
            return CollectionResult(artifactsCommitted: 0, artifactsRejected: 0,
                                    notes: ["no operator path supplied and no images found in ~/Downloads"], status: .partial)
        }

        var committed = 0
        var rejected = 0
        let now = Date()
        for url in targets {
            let path = url.path
            // SEC-DELTA-1/2: reject symlinks + over-256MB files before any read
            // (the path can be operator/agent-supplied or a ~/Downloads entry).
            guard let size = FileAnalyzerIO.regularFileSize(url) else { rejected += 1; continue }
            guard let src = CGImageSourceCreateWithURL(url as CFURL, nil),
                  let props = CGImageSourceCopyPropertiesAtIndex(src, 0, nil) as? [String: Any] else { continue }
            let width = (props[kCGImagePropertyPixelWidth as String] as? Int) ?? 0
            let height = (props[kCGImagePropertyPixelHeight as String] as? Int) ?? 0
            let dpi = (props[kCGImagePropertyDPIWidth as String] as? Double) ?? 0
            let colorModel = props[kCGImagePropertyColorModel as String] as? String ?? ""
            let gps = props[kCGImagePropertyGPSDictionary as String] as? [String: Any]
            let exif = props[kCGImagePropertyExifDictionary as String] as? [String: Any]
            let iptc = props[kCGImagePropertyIPTCDictionary as String] as? [String: Any]
            let tiff = props[kCGImagePropertyTIFFDictionary as String] as? [String: Any]

            // Real GPS coordinates (signed by hemisphere ref), not just a has_gps bool.
            var gpsLat: Double? = nil
            var gpsLon: Double? = nil
            if let gps {
                if let lat = gps[kCGImagePropertyGPSLatitude as String] as? Double {
                    gpsLat = (gps[kCGImagePropertyGPSLatitudeRef as String] as? String == "S") ? -lat : lat
                }
                if let lon = gps[kCGImagePropertyGPSLongitude as String] as? Double {
                    gpsLon = (gps[kCGImagePropertyGPSLongitudeRef as String] as? String == "W") ? -lon : lon
                }
            }
            // Real XMP (distinct from IPTC): the dedicated metadata container.
            let hasXMP: Bool = {
                guard let md = CGImageSourceCopyMetadataAtIndex(src, 0, nil),
                      let tags = CGImageMetadataCopyTags(md) as? [CGImageMetadataTag] else { return false }
                return !tags.isEmpty
            }()

            guard let sha = FileAnalyzerIO.streamingSHA256(url) else { rejected += 1; continue }
            var recordData: [String: JSONValue] = [
                "path": .string(path),
                "width": .integer(Int64(width)),
                "height": .integer(Int64(height)),
                "dpi": .double(dpi),
                "color_model": .string(colorModel),
                "has_gps": .bool(gps != nil),
                "has_exif": .bool(exif != nil),
                "has_iptc": .bool(iptc != nil),
                "has_xmp": .bool(hasXMP),
            ]
            if let gpsLat { recordData["gps_lat"] = .double(gpsLat) }
            if let gpsLon { recordData["gps_lon"] = .double(gpsLon) }
            if let make = tiff?[kCGImagePropertyTIFFMake as String] as? String { recordData["camera_make"] = .string(make) }
            if let model = tiff?[kCGImagePropertyTIFFModel as String] as? String { recordData["camera_model"] = .string(model) }
            if let sw = tiff?[kCGImagePropertyTIFFSoftware as String] as? String { recordData["software"] = .string(sw) }

            let geo = (gpsLat != nil && gpsLon != nil) ? String(format: " 📍 %.5f,%.5f", gpsLat!, gpsLon!) : ""
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
                summary: "Image \(url.lastPathComponent): \(width)x\(height) \(colorModel)\(geo)",
                sizeBytes: Int64(size),
                confidence: .observed,
                privacyClass: .metadata,
                actor: NSUserName(),
                data: recordData
            )
            do { try await output.commit(record); committed += 1 } catch { rejected += 1 }
        }
        return CollectionResult(artifactsCommitted: committed, artifactsRejected: rejected,
                                notes: ["image metadata: \(committed) image(s) analyzed"], status: .ok)
    }
}
