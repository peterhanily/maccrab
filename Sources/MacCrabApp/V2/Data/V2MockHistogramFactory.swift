// V2MockHistogramFactory.swift
// Procedural histogram data for the Overview chart, used by the
// mock provider AND as the fallback inside V2AlertHistogram when
// the live provider returns empty data.

import Foundation

public enum V2MockHistogramFactory {
    public static func synthBuckets(rangeKey: String) -> [V2OverviewBucket] {
        let now = Date()
        let (totalSpan, bucketSpan): (TimeInterval, TimeInterval) = {
            switch rangeKey {
            case "1h":  return (3_600,    300)
            case "6h":  return (21_600,   1_800)
            case "24h": return (86_400,   7_200)
            case "7d":  return (604_800,  43_200)
            default:    return (21_600,   1_800)
            }
        }()
        let count = Int(totalSpan / bucketSpan)
        return (0..<count).map { i in
            let end = now.addingTimeInterval(-bucketSpan * Double(count - i - 1))
            let start = end.addingTimeInterval(-bucketSpan)
            var lo = 0, med = 0, hi = 0, crit = 0
            let hum = Int(2 * (sin(Double(i) / 1.5) + 1))
            lo += hum
            switch rangeKey {
            case "1h":
                if i == 7 || i == 8 { hi += 2 }
                if i == 8 { crit += 1 }
            case "6h":
                if i == 7 { crit += 1; hi += 1 }
                if i == 8 { crit += 1; hi += 2; med += 1 }
                if i == 9 { hi += 1 }
                if i == 10 { med += 2 }
            case "24h":
                if i == 2 { hi += 1 }
                if i == 7 { crit += 1; hi += 1 }
                if i == 8 { crit += 2; hi += 3 }
                if i == 9 { hi += 1; med += 1 }
                if i == 10 { med += 1 }
                if i == 11 { lo += 1 }
            case "7d":
                if i == 1 { med += 2 }
                if i == 4 { hi += 1 }
                if i == 7 { hi += 2; med += 1 }
                if i == 8 { crit += 1; hi += 2 }
                if i == 9 { crit += 2; hi += 1 }
                if i == 12 { lo += 3 }
            default: break
            }
            return V2OverviewBucket(start: start, end: end,
                                    critical: crit, high: hi, medium: med, low: lo)
        }
    }
}
