// LLMBoundedHTTPReader.swift
// MacCrabCore
//
// A single streaming response boundary for every LLM completion backend.
// Provider responses are untrusted network input: never let URLSession buffer
// an arbitrarily large body before the service's 50 KB response policy runs.

import Foundation

/// Transport failures that need a distinct service-level disposition.
enum LLMBoundedHTTPError: Error, Equatable, Sendable {
    /// The peer declared or delivered more bytes than the completion boundary.
    /// `declaredBytes` is nil for chunked, absent, malformed, or understated
    /// Content-Length responses; the running byte count still enforces the cap.
    case responseTooLarge(limit: Int, declaredBytes: Int64?)
    case invalidResponse
}

struct LLMBoundedHTTPResponse: Sendable {
    let data: Data
    let response: HTTPURLResponse
}

/// Reads an HTTP response incrementally and owns cancellation of that transfer.
///
/// `URLSession.data(for:)` buffers the whole response before returning, so a
/// hostile or broken model endpoint can consume arbitrary memory even though
/// LLMService later rejects responses above 50 KB. `bytes(for:)` exposes the
/// headers before body iteration and yields bytes incrementally. The transfer
/// runs in its own dedicated task so an oversize response can cancel the underlying
/// URLSession work immediately without falsely cancelling the caller's logical
/// LLM request (which must be accounted as `response_oversize`, not
/// `cancellation`).
enum LLMBoundedHTTPReader {
    /// This is the same semantic boundary LLMService applies to decoded text.
    /// Keeping the transport and service guard on one shared constant prevents
    /// the five providers from drifting to different limits.
    static let maximumResponseBytes = 50_000

    static func read(
        request: URLRequest,
        using session: URLSession,
        maximumBytes: Int = maximumResponseBytes
    ) async throws -> LLMBoundedHTTPResponse {
        precondition(maximumBytes >= 0, "response byte cap must be non-negative")

        let transfer = Task<LLMBoundedHTTPResponse, Error> {
            let (bytes, response) = try await session.bytes(for: request)
            guard let http = response as? HTTPURLResponse else {
                throw LLMBoundedHTTPError.invalidResponse
            }

            let data = try await collect(
                response: http,
                bytes: bytes,
                maximumBytes: maximumBytes,
                cancelTransfer: {
                    // This closure executes inside `transfer`, not in the
                    // caller's task. Cancelling here tears down URLSession's
                    // AsyncBytes producer while preserving the caller's
                    // non-cancelled state for honest telemetry classification.
                    withUnsafeCurrentTask { task in
                        task?.cancel()
                    }
                }
            )
            return LLMBoundedHTTPResponse(data: data, response: http)
        }

        return try await withTaskCancellationHandler {
            try await transfer.value
        } onCancel: {
            // Conversely, genuine caller cancellation must promptly stop the
            // network transfer rather than leave it consuming a connection.
            transfer.cancel()
        }
    }

    /// Injectable byte-sequence core used by deterministic fixed-length,
    /// chunked, and no-length tests. Production passes URLSession.AsyncBytes.
    static func collect<Bytes: AsyncSequence>(
        response: HTTPURLResponse,
        bytes: Bytes,
        maximumBytes: Int,
        cancelTransfer: @escaping @Sendable () -> Void
    ) async throws -> Data where Bytes.Element == UInt8 {
        precondition(maximumBytes >= 0, "response byte cap must be non-negative")

        let expected = response.expectedContentLength
        if expected >= 0, expected > Int64(maximumBytes) {
            cancelTransfer()
            throw LLMBoundedHTTPError.responseTooLarge(
                limit: maximumBytes,
                declaredBytes: expected
            )
        }

        var data = Data()
        if expected > 0 {
            data.reserveCapacity(Int(expected))
        }

        for try await byte in bytes {
            // Exact-cap responses are valid. Reject before appending byte
            // cap+1, so retained memory is bounded by `maximumBytes` even
            // when Content-Length is absent, chunked, or dishonest.
            guard data.count < maximumBytes else {
                cancelTransfer()
                throw LLMBoundedHTTPError.responseTooLarge(
                    limit: maximumBytes,
                    declaredBytes: expected >= 0 ? expected : nil
                )
            }
            data.append(byte)
        }
        return data
    }
}
