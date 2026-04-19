# MacCrab Detection Rules

This directory contains the detection rules used by MacCrab's rule engine. Rules are written in a Sigma-compatible YAML format and compiled to JSON predicates before being loaded at runtime.

---

## Rule Format

Each rule is a standard [Sigma](https://sigmahq.io/) YAML file with `logsource.product: macos`. Rules define detection logic using field selectors, modifiers (`contains`, `endswith`, `startswith`, `re`, etc.), and boolean conditions.

MacCrab extends the Sigma format with **temporal sequence rules** (`type: sequence`), which define multi-step detection chains with time windows, ordering constraints, and process lineage correlation. See the main [README](../README.md) for detailed examples of both formats.

### Required Fields

Every rule must include:

| Field | Description |
|-------|-------------|
| `title` | Clear, concise name for the detection |
| `id` | Unique UUID (v4 format) |
| `status` | `stable`, `experimental`, or `test` |
| `description` | What the rule detects and why it matters |
| `author` | Author name or `MacCrab Community` |
| `date` | Creation date in `YYYY/MM/DD` format |
| `tags` | MITRE ATT&CK tags (e.g., `attack.execution`, `attack.t1059.004`) |
| `logsource` | Must include `product: macos` and a `category` |
| `detection` | Selection and condition logic |
| `falsepositives` | List of known false positive scenarios |
| `level` | Severity: `informational`, `low`, `medium`, `high`, or `critical` |

---

## Directory Organization

Rules are organized by [MITRE ATT&CK](https://attack.mitre.org/) tactic:

| Directory | Tactic | Rules |
|-----------|--------|:-----:|
| `defense_evasion/` | Defense Evasion (TA0005) | 62 |
| `credential_access/` | Credential Access (TA0006) | 35 |
| `persistence/` | Persistence (TA0003) | 34 |
| `supply_chain/` | Supply Chain (macOS-specific) | 31 |
| `execution/` | Execution (TA0002) | 31 |
| `discovery/` | Discovery (TA0007) | 24 |
| `privilege_escalation/` | Privilege Escalation (TA0004) | 21 |
| `ai_safety/` | AI Agent Safety (macOS-specific) | 19 |
| `command_and_control/` | Command and Control (TA0011) | 17 |
| `lateral_movement/` | Lateral Movement (TA0008) | 16 |
| `collection/` | Collection (TA0009) | 15 |
| `exfiltration/` | Exfiltration (TA0010) | 12 |
| `initial_access/` | Initial Access (TA0001) | 11 |
| `tcc/` | TCC Abuse (macOS-specific) | 9 |
| `container/` | Container Security (macOS-specific) | 8 |
| `impact/` | Impact (TA0040) | 8 |
| `sequences/` | Temporal sequence rules (multi-tactic) | 27 |
| **Total** | | **380** |

Sequence rules in `sequences/` span multiple tactics. They are stored separately because they use the extended sequence format and are processed by the `SequenceEngine` rather than the standard `RuleEngine`.

---

## Adding a New Rule

1. Choose the appropriate tactic directory (or `sequences/` for multi-step rules).

2. Create a new `.yml` file with a descriptive filename using snake_case:
   ```
   Rules/execution/my_new_detection.yml
   ```

3. Assign a unique UUID v4 as the rule `id`. You can generate one with:
   ```bash
   python3 -c "import uuid; print(uuid.uuid4())"
   ```

4. Write the detection logic using Sigma field names and modifiers. MacCrab supports the following Sigma field names mapped to macOS event attributes:

   | Sigma Field | Maps To |
   |-------------|---------|
   | `Image` | Process executable path |
   | `CommandLine` | Full command line |
   | `ParentImage` | Parent process executable path |
   | `User` | Process user name |
   | `TargetFilename` | File path (for file events) |
   | `SourceFilename` | Source file path (for renames) |
   | `DestinationIp` | Network destination IP |
   | `DestinationPort` | Network destination port |
   | `DestinationHostname` | Network destination hostname |
   | `SignerType` | Code signature signer type |

5. Tag the rule with the appropriate MITRE ATT&CK tactic and technique identifiers.

6. Document any known false positives.

7. Compile and verify:
   ```bash
   python3 Compiler/compile_rules.py --input-dir Rules/ \
       --output-dir ~/Library/Application\ Support/MacCrab/compiled_rules/
   ```

---

## Compiling Rules

Rules must be compiled from YAML to JSON before MacCrab can load them. The compiler validates rule structure, maps Sigma field names to internal field paths, and outputs one JSON file per rule:

```bash
python3 Compiler/compile_rules.py \
    --input-dir Rules/ \
    --output-dir ~/Library/Application\ Support/MacCrab/compiled_rules/
```

The compiler requires Python 3.9+ and PyYAML (`pip install pyyaml`).

---

## License

All detection rules in this directory are licensed under the [Detection Rule License 1.1 (DRL 1.1)](https://github.com/SigmaHQ/Detection-Rule-License).

You are free to use these rules for security monitoring and detection. If you redistribute them, you must retain the original license and attribution. See the DRL 1.1 text for full terms.
