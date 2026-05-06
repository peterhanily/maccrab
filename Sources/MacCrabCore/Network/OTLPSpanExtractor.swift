// OTLPSpanExtractor.swift
// MacCrabCore
//
// v1.9 PR-3b — converts a decoded OTLP `ExportTraceServiceRequest`
// (`[OTLPRawResourceGroup]`) into a list of `SpanRecord` ready for
// `TraceStore.insertSpan(_:)`. Three responsibilities:
//
//   1. Run each span's attributes through `OTLPAttributeSanitizer` so any
//      secret-shaped values are redacted before persistence.
//   2. Resolve `agent_tool` per Plan v3 review #8 ordering:
//        a. Span name prefix (`claude_code.*`, `codex.*`, ...)
//        b. service.name exact match (set in OTel SDK config)
//        c. gen_ai.provider.name (current OTel GenAI semconv 1.41+)
//        d. gen_ai.system (legacy/deprecated, still emitted by Claude Code)
//        e. nil — caller's lineage fallback in EventLoop runs anyway.
//      Earlier sources outrank later ones; ties prefer the earlier source.
//      When (a) and a hypothetical lineage step disagree, we don't know
//      lineage at extractor time — that conflict is detected and
//      logged in EventLoop, NOT here. PR-3b emits the value the
//      extractor sees; the conflict counter increments downstream.
//   3. Pluck `service.name`, `gen_ai.provider.name`, and `gen_ai.system`
//      onto each `SpanRecord` so the row is self-describing without
//      needing a join back to the resource scope.

import Foundation

public struct OTLPSpanExtractionResult: Sendable {
    public let spans: [SpanRecord]
    public let totalAttributesPersisted: Int
    public let totalAttributesKeyRedacted: Int
    public let totalAttributesValueRedacted: Int
}

public enum OTLPSpanExtractor {

    /// Walk all decoded resource groups, sanitise per-span attributes, and
    /// resolve agent_tool. Return SpanRecords + telemetry counts.
    ///
    /// v1.9.0 audit (Sec-H1): the four free-form span identity fields
    /// (`service.name`, `span.name`, `gen_ai.provider.name`,
    /// `gen_ai.system`) ALSO pass through `OTLPAttributeSanitizer.redactString`
    /// before persistence. Those columns land in `traces.db` in
    /// plaintext (only `attributes_json` is column-encrypted), and a
    /// hostile or buggy agent could embed a literal secret in them —
    /// e.g. `span.name = "tool.invoke(sk-ant-…)"`. Pre-fix, that
    /// secret would have survived. Resolution order: sanitise FIRST,
    /// then resolve `agent_tool` against the sanitised values. The
    /// vendor regexes are anchored at word boundaries with prefix +
    /// length requirements that don't bite the legitimate values
    /// (`claude-code`, `anthropic`, `cursor`, etc.) used by the
    /// agent_tool resolver.
    public static func extract(
        from groups: [OTLPRawResourceGroup]
    ) -> OTLPSpanExtractionResult {
        var spans: [SpanRecord] = []
        var totalPersisted = 0
        var totalKeyRedacted = 0
        var totalValueRedacted = 0

        for group in groups {
            // Sanitise the resource-level service.name BEFORE using it
            // for any span in this group.
            let serviceName = group.serviceName.map(OTLPAttributeSanitizer.redactString)

            for raw in group.spans {
                let sanitised = OTLPAttributeSanitizer.sanitize(raw.attributes)
                totalPersisted += sanitised.attributesPersisted
                totalKeyRedacted += sanitised.attributesKeyRedacted
                totalValueRedacted += sanitised.attributesValueRedacted

                // Pull provider + legacy gen_ai.system out of the
                // attribute set. Sanitise each before persistence.
                var providerName: String? = nil
                var legacyGenAi: String? = nil
                for (k, v) in raw.attributes {
                    switch k {
                    case "gen_ai.provider.name":
                        providerName = OTLPAttributeSanitizer.redactString(v)
                    case "gen_ai.system":
                        legacyGenAi = OTLPAttributeSanitizer.redactString(v)
                    default:
                        break
                    }
                }

                let sanitisedSpanName = OTLPAttributeSanitizer.redactString(raw.name)

                let agentTool = resolveAgentTool(
                    spanName: sanitisedSpanName,
                    serviceName: serviceName,
                    providerName: providerName,
                    legacyGenAiSystem: legacyGenAi
                )

                spans.append(SpanRecord(
                    traceId: raw.traceIdHex,
                    spanId: raw.spanIdHex,
                    parentSpanId: raw.parentSpanIdHex.isEmpty ? nil : raw.parentSpanIdHex,
                    startNs: raw.startTimeUnixNano,
                    endNs: raw.endTimeUnixNano,
                    serviceName: serviceName,
                    spanName: sanitisedSpanName,
                    agentTool: agentTool,
                    providerName: providerName,
                    legacyGenAiSystem: legacyGenAi,
                    attributesJson: sanitised.attributesJson
                ))
            }
        }

        return OTLPSpanExtractionResult(
            spans: spans,
            totalAttributesPersisted: totalPersisted,
            totalAttributesKeyRedacted: totalKeyRedacted,
            totalAttributesValueRedacted: totalValueRedacted
        )
    }

    /// Plan v3 review #8 ordering. Returns nil when no signal lines up;
    /// EventLoop's lineage fallback handles the rest.
    public static func resolveAgentTool(
        spanName: String,
        serviceName: String?,
        providerName: String?,
        legacyGenAiSystem: String?
    ) -> AIToolType? {
        // 1. Span name prefix — set by the agent's instrumentation code,
        //    hardest to misconfigure.
        if spanName.hasPrefix("claude_code.") { return .claudeCode }
        if spanName.hasPrefix("codex.")      { return .codex }
        if spanName.hasPrefix("cursor.")     { return .cursor }
        if spanName.hasPrefix("copilot.")    { return .copilot }
        if spanName.hasPrefix("aider.")      { return .aider }
        if spanName.hasPrefix("continue.")   { return .continuedev }
        if spanName.hasPrefix("windsurf.")   { return .windsurf }
        // 2. service.name — set by OTel SDK config; easier to misconfigure
        //    but still definitive when correct.
        if let s = serviceName {
            switch s {
            case "claude-code", "claude_code":   return .claudeCode
            case "codex", "openai-codex":        return .codex
            case "cursor":                       return .cursor
            case "copilot", "github-copilot":    return .copilot
            case "aider":                        return .aider
            case "continue":                     return .continuedev
            case "windsurf":                     return .windsurf
            default: break
            }
        }
        // 3 + 4. Provider / legacy gen_ai.system — least specific signal,
        //    can identify provider but not necessarily the agent tool. We
        //    map "anthropic" → claudeCode only when no other signal won.
        //    Fallback is bounded; downstream lineage walk will refine.
        let provider = providerName ?? legacyGenAiSystem
        if let p = provider?.lowercased() {
            switch p {
            case "anthropic":   return .claudeCode
            case "openai":      return .codex
            // Other providers don't map cleanly to a single agent tool —
            // multiple agents can hit the same provider — so we emit nil
            // and let the lineage fallback decide.
            default: break
            }
        }
        return nil
    }
}
