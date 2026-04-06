# MacCrab Feature Checklist

Every new feature MUST complete ALL items before merge. This ensures consistency across docs, localization, accessibility, and testing.

## Required for Every New Feature

### Code
- [ ] Feature compiles with zero warnings
- [ ] All existing tests still pass
- [ ] New tests written for the feature (minimum 2 per component)

### Documentation
- [ ] README.md updated with new feature (if user-facing)
- [ ] Rule count badge updated if rules were added
- [ ] Architecture diagram updated if new engine/collector added
- [ ] CLI help text updated if new commands added

### Localization
- [ ] All user-facing strings wrapped with `String(localized:defaultValue:)`
- [ ] New keys added to `en.lproj/Localizable.strings`
- [ ] New keys added to ALL 13 translation files (es, fr, de, ja, zh-Hans, ko, pt-BR, it, nl, zh-Hant, ru, sv, pl)

### Accessibility
- [ ] `.accessibilityLabel()` on every interactive element (Button, Toggle, Picker, TextField)
- [ ] `.accessibilityHint()` on complex actions (describe what happens)
- [ ] `.accessibilityElement(children: .combine)` on grouped components (cards, rows)
- [ ] Animations wrapped in `@Environment(\.accessibilityReduceMotion)` check
- [ ] No color-only information — always pair with text or icon

### Dashboard UI (if feature has UI)
- [ ] View added to appropriate tab
- [ ] Consistent with existing layout patterns (GroupBox, HStack spacing)
- [ ] Flexible frame widths (min/ideal/max, no hardcoded)
- [ ] Works in ScrollView
- [ ] Empty state handled

### Daemon Integration (if feature has backend)
- [ ] Engine initialized in main.swift
- [ ] Event processing task created if needed
- [ ] Wired into maintenance timer if periodic
- [ ] Startup banner updated with status
- [ ] Graceful degradation if dependency unavailable

### Prevention/Response (if feature blocks/modifies)
- [ ] Gated behind opt-in toggle or env var
- [ ] Confirmation dialog before destructive action
- [ ] Can be disabled without restart
- [ ] Audit log entry created for every action

### Rules (if detection rules added)
- [ ] Sigma YAML format validated
- [ ] Rule lint passes (`./scripts/rule-lint.sh`)
- [ ] Rules compile (`python3 Compiler/compile_rules.py`)
- [ ] Filter blocks for system processes included
- [ ] MITRE ATT&CK tags present
- [ ] False positives documented

### Security
- [ ] No string interpolation in SQL or shell commands
- [ ] User input validated before use
- [ ] Secrets not logged or stored in plaintext
- [ ] File permissions appropriate (0o640 for data, 0o750 for dirs)
