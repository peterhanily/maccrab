// UltrasonicMonitor.swift
// MacCrabCore
//
// Monitors the microphone for ultrasonic voice injection attacks.
// Periodically samples audio and performs FFT analysis using the
// Accelerate framework to detect energy above 18 kHz that may
// indicate DolphinAttack, NUIT, or SurfingAttack patterns.

import Foundation
import AVFoundation
import Accelerate
import os.log

/// Monitors the microphone for ultrasonic voice injection attacks.
/// Detects DolphinAttack (25.5 kHz), NUIT (19.5 kHz), and SurfingAttack (23 kHz)
/// patterns by analyzing the frequency spectrum for energy above 18 kHz.
///
/// Requires microphone permission (TCC).
public actor UltrasonicMonitor {
    private let logger = Logger(subsystem: "com.maccrab", category: "ultrasonic-monitor")

    public struct UltrasonicEvent: Sendable {
        public let attackType: AttackType
        public let peakFrequencyHz: Float
        public let energyRatio: Float      // Ultrasonic energy / speech energy in dB
        public let confidence: Float       // 0-1
        public let timestamp: Date
    }

    public enum AttackType: String, Sendable {
        case dolphinAttack = "dolphin_attack"     // ~25.5 kHz
        case nuit = "nuit"                         // ~19.5 kHz near-ultrasonic
        case surfingAttack = "surfing_attack"      // ~23 kHz
        case unknownUltrasonic = "unknown_ultrasonic"
    }

    public nonisolated let events: AsyncStream<UltrasonicEvent>
    private var continuation: AsyncStream<UltrasonicEvent>.Continuation?
    private var monitorTask: Task<Void, Never>?

    /// Analysis parameters
    private let sampleRate: Float = 48000  // 48 kHz captures up to 24 kHz (Nyquist)
    private let fftSize: Int = 4096        // ~11.7 Hz resolution at 48 kHz
    private let ultrasonicThreshold: Float = 18000  // Hz — above this is ultrasonic
    private let speechBandLow: Float = 300
    private let speechBandHigh: Float = 8000
    private let energyRatioThreshold: Float = -6  // dB — ultrasonic must be within 6dB of speech
    private let sampleDuration: TimeInterval = 1.0  // Sample 1 second every interval
    private let pollInterval: TimeInterval

    public init(pollInterval: TimeInterval = 30) {
        self.pollInterval = pollInterval
        var capturedContinuation: AsyncStream<UltrasonicEvent>.Continuation!
        self.events = AsyncStream(bufferingPolicy: .bufferingNewest(32)) { c in
            capturedContinuation = c
        }
        self.continuation = capturedContinuation
    }

    public func start() {
        guard monitorTask == nil else { return }
        logger.info("Ultrasonic monitor starting (sample every \(self.pollInterval)s)")

        monitorTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.analyzeSample()
                try? await Task.sleep(nanoseconds: UInt64((self?.pollInterval ?? 30) * 1_000_000_000))
            }
        }
    }

    public func stop() {
        monitorTask?.cancel()
        monitorTask = nil
        continuation?.finish()
    }

    private func analyzeSample() {
        // Record a short audio sample using AVAudioEngine
        // This requires microphone TCC permission

        let engine = AVAudioEngine()
        let inputNode = engine.inputNode
        let format = inputNode.outputFormat(forBus: 0)

        // Verify sample rate is high enough
        guard format.sampleRate >= 44100 else {
            logger.warning("Sample rate \(format.sampleRate) too low for ultrasonic detection (need >= 44100)")
            return
        }

        let actualSampleRate = Float(format.sampleRate)
        var samples: [Float] = []
        let expectedSamples = Int(actualSampleRate * Float(sampleDuration))

        let semaphore = DispatchSemaphore(value: 0)

        inputNode.installTap(onBus: 0, bufferSize: AVAudioFrameCount(expectedSamples), format: format) { buffer, _ in
            guard let channelData = buffer.floatChannelData else { return }
            let frameCount = Int(buffer.frameLength)
            let data = Array(UnsafeBufferPointer(start: channelData[0], count: frameCount))
            samples.append(contentsOf: data)
            if samples.count >= expectedSamples {
                semaphore.signal()
            }
        }

        do {
            try engine.start()
        } catch {
            logger.debug("Cannot access microphone: \(error.localizedDescription)")
            return
        }

        // Wait for sample (with timeout)
        let result = semaphore.wait(timeout: .now() + sampleDuration + 1.0)
        inputNode.removeTap(onBus: 0)
        engine.stop()

        guard result == .success, samples.count >= fftSize else { return }

        // Perform FFT analysis
        let spectrum = computeSpectrum(samples: Array(samples.prefix(fftSize)), sampleRate: actualSampleRate)

        // Check for ultrasonic energy
        if let event = analyzeSpectrum(spectrum, sampleRate: actualSampleRate) {
            continuation?.yield(event)
            logger.warning("Ultrasonic attack detected: \(event.attackType.rawValue) at \(event.peakFrequencyHz) Hz (confidence: \(event.confidence))")
        }
    }

    /// Compute magnitude spectrum using Accelerate vDSP FFT.
    private func computeSpectrum(samples: [Float], sampleRate: Float) -> [Float] {
        let n = samples.count
        let log2n = vDSP_Length(log2(Float(n)))

        guard let fftSetup = vDSP_create_fftsetup(log2n, FFTRadix(FFT_RADIX2)) else {
            return []
        }
        defer { vDSP_destroy_fftsetup(fftSetup) }

        // Apply Hann window
        var windowed = [Float](repeating: 0, count: n)
        var window = [Float](repeating: 0, count: n)
        vDSP_hann_window(&window, vDSP_Length(n), Int32(vDSP_HANN_NORM))
        vDSP_vmul(samples, 1, window, 1, &windowed, 1, vDSP_Length(n))

        // Split complex for FFT
        var realp = [Float](repeating: 0, count: n / 2)
        var imagp = [Float](repeating: 0, count: n / 2)

        realp.withUnsafeMutableBufferPointer { realBuf in
            imagp.withUnsafeMutableBufferPointer { imagBuf in
                var splitComplex = DSPSplitComplex(realp: realBuf.baseAddress!, imagp: imagBuf.baseAddress!)
                windowed.withUnsafeBytes { rawBuf in
                    let complexBuf = rawBuf.bindMemory(to: DSPComplex.self)
                    vDSP_ctoz(complexBuf.baseAddress!, 2, &splitComplex, 1, vDSP_Length(n / 2))
                }
                vDSP_fft_zrip(fftSetup, &splitComplex, 1, log2n, FFTDirection(FFT_FORWARD))
            }
        }

        // Compute magnitudes
        var magnitudes = [Float](repeating: 0, count: n / 2)
        realp.withUnsafeMutableBufferPointer { realBuf in
            imagp.withUnsafeMutableBufferPointer { imagBuf in
                var splitComplex = DSPSplitComplex(realp: realBuf.baseAddress!, imagp: imagBuf.baseAddress!)
                vDSP_zvmags(&splitComplex, 1, &magnitudes, 1, vDSP_Length(n / 2))
            }
        }

        // Convert to dB
        var dbMagnitudes = [Float](repeating: 0, count: n / 2)
        var one: Float = 1.0
        vDSP_vdbcon(magnitudes, 1, &one, &dbMagnitudes, 1, vDSP_Length(n / 2), 0)

        return dbMagnitudes
    }

    /// Analyze spectrum for ultrasonic attack patterns.
    private func analyzeSpectrum(_ spectrum: [Float], sampleRate: Float) -> UltrasonicEvent? {
        guard !spectrum.isEmpty else { return nil }

        let binWidth = sampleRate / Float(spectrum.count * 2)

        // Calculate energy in speech band (300-8000 Hz)
        let speechLowBin = Int(speechBandLow / binWidth)
        let speechHighBin = min(Int(speechBandHigh / binWidth), spectrum.count - 1)
        let ultrasonicLowBin = Int(ultrasonicThreshold / binWidth)

        guard speechLowBin < speechHighBin, ultrasonicLowBin < spectrum.count else { return nil }

        let speechEnergy = spectrum[speechLowBin...speechHighBin].reduce(0, +) / Float(speechHighBin - speechLowBin)
        let ultrasonicBins = spectrum[ultrasonicLowBin...]
        let ultrasonicEnergy = ultrasonicBins.reduce(0, +) / Float(ultrasonicBins.count)

        let energyRatio = ultrasonicEnergy - speechEnergy  // dB difference

        // Only flag if ultrasonic energy is significant relative to speech
        guard energyRatio > energyRatioThreshold else { return nil }

        // Find peak frequency in ultrasonic band
        guard let peakBinOffset = ultrasonicBins.enumerated().max(by: { $0.element < $1.element })?.offset else {
            return nil
        }
        let peakFreq = Float(ultrasonicLowBin + peakBinOffset) * binWidth

        // Classify attack type by frequency
        let attackType: AttackType
        let confidence: Float

        if peakFreq >= 24000 && peakFreq <= 27000 {
            attackType = .dolphinAttack
            confidence = min(1.0, (energyRatio + 6) / 20)  // Scale 0-1
        } else if peakFreq >= 18500 && peakFreq <= 21000 {
            attackType = .nuit
            confidence = min(1.0, (energyRatio + 6) / 15)
        } else if peakFreq >= 22000 && peakFreq <= 24000 {
            attackType = .surfingAttack
            confidence = min(1.0, (energyRatio + 6) / 18)
        } else {
            attackType = .unknownUltrasonic
            confidence = min(1.0, (energyRatio + 6) / 20)
        }

        return UltrasonicEvent(
            attackType: attackType,
            peakFrequencyHz: peakFreq,
            energyRatio: energyRatio,
            confidence: confidence,
            timestamp: Date()
        )
    }
}
