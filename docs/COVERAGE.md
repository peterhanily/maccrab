# Detection Coverage

This page is **generated** from `Rules/*.yml` by
`scripts/generate-coverage-doc.py`. Don't hand-edit — re-run
the script when rules change. Last rebuild: walks every YAML
under `Rules/` and groups by tactic dir + extracts MITRE
ATT&CK technique tags from each rule's `tags:` block.

## At a glance

| Metric | Count |
|---|---|
| Rules total | **483** (436 single-event + 41 sequence + 6 graph) |
| Status: stable | 90 |
| Status: experimental | 374 |
| Status: deprecated | 10 |
| Severity: critical | 19 |
| Severity: high | 111 |
| Severity: medium | 226 |
| Severity: low | 112 |
| Severity: informational | 9 |
| Distinct MITRE ATT&CK techniques covered | 170 |
| Tactic directories | 18 |

## Caveat

This is **documented coverage** — what each rule's `tags:`
block declares it matches. It is NOT an executed benchmark
against a labeled malware corpus. False-positive rate per
rule under real workloads is currently measured
opportunistically via field reports + the audit script's
FP-risk pass (rules without `filter:` blocks). A formal
benchmark + FP-rate publication is on the v1.9 roadmap.

## By tactic

### AI Safety (MacCrab-specific) (32 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `agent_filesystem_violation_high_conf.yml`<br/>Agent Wrote To Privileged Path (High Confidence) | stable | high | T1543.001 T1543.004 T1555.001 |
| `agent_filesystem_violation_probable.yml`<br/>Agent Wrote To Privileged Path (Lineage Attribution) | stable | medium | T1543.001 T1543.004 T1555.001 |
| `agent_traceparent_credential_access.yml`<br/>Agent Read Credential Material (Traceparent-Bound) | stable | high | T1552.001 T1552.004 T1555 |
| `agent_writes_outside_project_to_dotfiles.yml`<br/>AI Coding Tool Writes to Shell Dotfile Outside Project | experimental | medium | T1546.004 |
| `ai_tool_data_exfiltration.yml`<br/>AI Tool Child Process Uploads Data to Non-Standard Destination | experimental | medium | T1041 T1048.003 T1071.001 |
| `ai_tool_downloads_script.yml`<br/>AI Coding Tool Downloads and Executes Script | stable | medium | T1059.004 |
| `ai_tool_encoded_payload.yml`<br/>Encoded Payload in AI Tool Command | experimental | low | T1027 |
| `ai_tool_installs_package.yml`<br/>AI Coding Tool Installs Package | experimental | low | T1195.001 |
| `ai_tool_modifies_git_config.yml`<br/>AI Coding Tool Modifies Global Git Configuration | experimental | low | T1543 |
| `ai_tool_modifies_shell_profile.yml`<br/>AI Tool Modifies Shell Profile | test | medium | T1546.004 |
| `ai_tool_prompt_injection.yml`<br/>Prompt Injection Pattern in AI Tool Command | test | low | T1195.001 |
| `ai_tool_reads_aws_credentials.yml`<br/>AI Coding Tool Accesses AWS Credentials | stable | low | T1552.001 |
| `ai_tool_reads_env_file.yml`<br/>AI Coding Tool Accesses Environment File | stable | low | T1552.001 |
| `ai_tool_reads_ssh_keys.yml`<br/>AI Coding Tool Accesses SSH Private Key | stable | medium | T1552.004 |
| `ai_tool_runs_sudo.yml`<br/>AI Coding Tool Child Runs Sudo | stable | medium | T1548.003 |
| `ai_tool_spawns_shell.yml`<br/>AI Coding Tool Spawns Shell Process (Enrichment) | test | informational | T1059.004 |
| `ai_tool_suspicious_download.yml`<br/>AI Tool Downloads File from Unusual Source | experimental | low | T1105 |
| `ai_tool_unapproved_network.yml`<br/>AI Tool Connects to Unapproved Network Destination | experimental | medium | T1041 T1071.001 |
| `ai_tool_writes_outside_project.yml`<br/>AI Tool Process Writes File Outside Project Directory | experimental | medium | T1036 |
| `ai_tool_writes_persistence.yml`<br/>AI Tool Installs Persistence Mechanism | stable | high | T1543.001 |
| `binary_dropped_into_claude_dir.yml`<br/>Executable Dropped Into .claude/ Subdirectory (SessionStart Hijack) | experimental | high | T1195.001 T1546 T1564.001 |
| `canary_skill_or_rules_read.yml`<br/>AI-Agent Honey-Prompt File Read | experimental | critical | T1083 |
| `claude_code_project_config_rce.yml`<br/>Claude Code Project Config Hook RCE Pattern | experimental | high | T1059 T1546 |
| `claude_settings_hook_injection_by_non_claude.yml`<br/>~/.claude/settings.json Modified by Non-Claude Process (Hook Injection) | experimental | high | T1195.001 T1546 |
| `honeyprompt_canary_package_install.yml`<br/>Honey-Prompt Canary Package Install Attempted | experimental | critical | T1195.001 |
| `llm_classifier_high_risk_intent.yml`<br/>MacCrab IntentClassifier Returned High-Risk Verdict | experimental | medium | T1195 |
| `mcp_server_added.yml`<br/>MCP Server Configuration Added | stable | low | T1195.002 |
| `mcp_server_config_injection_by_non_ai_tool.yml`<br/>MCP Server Config Modified by Package-Manager Lineage (SANDWORM_MODE / Shai-Hulud) | experimental | high | T1195.001 T1546 T1546.016 |
| `mcp_server_suspicious_command.yml`<br/>MCP Server with Suspicious Command Path | stable | medium | T1036 T1059 |
| `mcp_server_tool_poisoning.yml`<br/>MCP Server with Potential Tool Description Injection | stable | high | T1059 T1195.002 |
| `skill_md_poisoning_install.yml`<br/>SKILL.md Poisoning — Install of Untrusted Agent Skill | experimental | high | T1059 T1546 |
| `vscode_tasks_json_modified_by_non_vscode.yml`<br/>.vscode/tasks.json Modified by Non-Editor Process (Folder-Open Hook Injection) | experimental | medium | T1195.001 T1546 |

### Collection (TA0009) (13 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `airdrop_file_staging.yml`<br/>Credential Or Keystore File Staged In AirDrop Directory | experimental | medium | T1011 T1552 |
| `browser_extension_suspicious.yml`<br/>Browser Extension Manifest or Package Modified Outside Browser Process | experimental | medium | T1176 |
| `calendar_database_access.yml`<br/>Calendar Database Accessed By Non-Calendar Process | experimental | low | T1005 |
| `clipboard_monitoring.yml`<br/>Clipboard Access By Non-Terminal Process | experimental | low | T1115 |
| `contacts_database_access.yml`<br/>Contacts Database Accessed By Non-Contacts Process | experimental | low | T1005 |
| `keylogger_event_tap.yml`<br/>CGEventTap API Reference In Command Line By Non-Apple Process | experimental | medium | T1056.001 |
| `keylogger_event_tap_active.yml`<br/>Active CGEventTap Monitoring Keyboard Input | stable | high | T1056.001 |
| `microphone_access_unsigned.yml`<br/>Microphone Access by Unsigned Process | stable | high | T1123 |
| `photos_library_access.yml`<br/>Photos Library Accessed By Non-Photos Process | experimental | low | T1005 |
| `screen_recording_tool.yml`<br/>Video Screen Recording via screencapture | experimental | medium | T1113 |
| `screenshot_by_non_system.yml`<br/>Screencapture Invocation By Non-System Process | experimental | medium | T1113 |
| `usb_mass_storage_connected.yml`<br/>Disk Image Or Volume Mount From Non-System Process | experimental | informational | T1200 T1204.002 |
| `voice_memo_access.yml`<br/>Voice Memo Files Accessed by Unusual Process | experimental | low | T1123 |

### Command & Control (TA0011) (20 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `c2_azurestaticprovider_net.yml`<br/>C2 Connection to sh.azurestaticprovider.net / 37.16.75.69 (Mini Shai-Hulud) | experimental | critical | T1071.001 T1102 T1195.001 |
| `c2_beacon_pattern.yml`<br/>Regular C2 Beacon Pattern Detected | experimental | low | T1071.001 |
| `c2_trackpipe_dev.yml`<br/>C2 Connection to trackpipe.dev (OpenClaw / GhostLoader) | experimental | critical | T1071.001 T1102 T1195.001 |
| `curl_to_raw_ip.yml`<br/>curl or wget Connection to Raw IP Address | experimental | medium | T1071.001 |
| `dns_high_entropy_query.yml`<br/>High-Entropy DNS Query (Possible DGA or Tunneling) | experimental | low | T1568.002 |
| `dns_over_https_manual.yml`<br/>Manual DNS-over-HTTPS Query to Bypass Local DNS | experimental | medium | T1071.004 |
| `doh_evasion_non_browser.yml`<br/>DNS-over-HTTPS by Non-Browser Process | experimental | medium | T1071.004 |
| `iodine_dns_tunnel.yml`<br/>DNS Tunneling Tool Detected (iodine/dns2tcp) | stable | high | T1071.004 |
| `launchctl_load_remote.yml`<br/>launchctl Loading from Remote or Temp Path | stable | medium | T1543.001 |
| `netcat_listener.yml`<br/>Netcat Listener Established | stable | medium | T1095 |
| `ngrok_or_tunnel.yml`<br/>Tunnel Service Tool Detected (ngrok/cloudflared/bore) | stable | medium | T1572 |
| `outbound_connection_unusual_port.yml`<br/>Outbound Connection on Unusual Port from Unsigned Binary | experimental | low | T1571 |
| `python_http_server.yml`<br/>Python HTTP Server Spawned | experimental | low | T1071.001 |
| `python_socket_server.yml`<br/>Python Socket Server or HTTP Server Bound to All Interfaces | experimental | low | T1071.001 |
| `reverse_shell_pattern.yml`<br/>Reverse Shell Command Detected | stable | critical | T1059.004 |
| `socat_relay.yml`<br/>Socat TCP Relay or Command Execution | stable | medium | T1095 |
| `ssh_reverse_tunnel.yml`<br/>SSH Reverse Tunnel Established | stable | medium | T1572 |
| `ssh_tunnel_established.yml`<br/>SSH Tunnel with Port Forwarding Established | experimental | medium | T1572 |
| `token_revocation_polling_loop.yml`<br/>Periodic api.github.com /user Poll From Non-TTY Lineage (Dead-Man's-Switch Watchdog) | experimental | medium | T1071.001 T1102 |
| `tor_proxy_connection.yml`<br/>Connection to Known Tor Network Ports | experimental | medium | T1090.003 |

### Container (MacCrab-specific) (12 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `docker_cap_add_dangerous.yml`<br/>Docker Container Granted Dangerous Linux Capabilities | experimental | medium | T1610 T1611 |
| `docker_exec_shell.yml`<br/>Docker Exec Spawns Interactive Shell | experimental | low | T1609 |
| `docker_host_network.yml`<br/>Docker Container Uses Host Network Namespace | experimental | low | T1611 |
| `docker_host_pid_namespace.yml`<br/>Docker Container Uses Host PID Namespace | experimental | medium | T1611 |
| `docker_image_layer_tamper.yml`<br/>Docker Image Layer Tampering via Export and Archive Manipulation | experimental | low | T1195.002 T1565.001 |
| `docker_namespace_escape.yml`<br/>Container Namespace Escape via nsenter | experimental | medium | T1611 |
| `docker_privileged_container.yml`<br/>Docker Privileged Container Launched | experimental | medium | T1610 T1611 |
| `docker_remote_api_access.yml`<br/>Docker Remote API Accessed via Plaintext TCP | experimental | medium | T1021 T1609 |
| `docker_sensitive_volume_mount.yml`<br/>Docker Container Mounts Sensitive Host Path | experimental | medium | T1552.001 T1611 |
| `docker_socket_access.yml`<br/>Non-Docker Process Accesses Docker Socket | experimental | medium | T1611 |
| `docker_socket_mount.yml`<br/>Docker Socket Mounted Into Container | experimental | medium | T1611 |
| `kubernetes_service_account_token.yml`<br/>Kubernetes Service Account Token Read from Unexpected Process | experimental | medium | T1552 T1552.007 |

### Credential Access (TA0006) (37 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `auth_brute_force.yml`<br/>Sudo Stdin Password Or Keychain Unlock By Non-Apple Process | experimental | low | T1110 T1555.001 |
| `authorization_plugin_non_apple.yml`<br/>Non-Apple Authorization Plugin Installed | stable | high | T1556.003 |
| `aws_credentials_accessed.yml`<br/>AWS Credential Files Accessed by Unusual Process | experimental | medium | T1552.001 |
| `browser_cookie_access.yml`<br/>Browser Cookie Database Accessed by Non-Browser | experimental | high | T1539 |
| `certificates_exported.yml`<br/>Certificate or PKCS12 Export via security Command | stable | medium | T1552.004 |
| `chrome_login_data_copied.yml`<br/>Chrome Login Data Database Copied by Non-Chrome Process | stable | high | T1555.003 |
| `credential_dump_via_dscl.yml`<br/>Credential Extraction via dscl Directory Service | experimental | high | T1003 |
| `crypto_wallet_data_access.yml`<br/>Cryptocurrency Wallet Data Accessed by Untrusted Process | experimental | high | T1555 |
| `gcore_keychain_exploit.yml`<br/>gcore Keychain Key Extraction (CVE-2025-24204) | experimental | critical | T1003.007 T1555.001 |
| `git_credential_helper_abuse.yml`<br/>Git Credential Helper Invoked by Non-Git Process | experimental | medium | T1555 |
| `keychain_cli_extract.yml`<br/>Keychain Password Extraction via security CLI | deprecated | medium | T1555.001 |
| `keychain_db_direct_read.yml`<br/>Direct Keychain Database File Access | experimental | high | T1555.001 |
| `keychain_dump_via_security.yml`<br/>Keychain Dump via security CLI | stable | medium | T1555.001 |
| `keychain_file_accessed.yml`<br/>login.keychain or System.keychain Database Opened by Non-Apple Process | experimental | high | T1555.001 |
| `keychain_unlock_by_non_system.yml`<br/>Keychain Unlock by Non-System Process | experimental | medium | T1003 T1555.001 |
| `mail_database_access.yml`<br/>Mail.app Database Accessed by Non-Mail Process | experimental | medium | T1114.001 |
| `memory_dump_credential_tools.yml`<br/>Memory Dump Tool Attached to Credential Process | experimental | high | T1003 |
| `memory_read_of_high_value_process.yml`<br/>Memory Read / Trace of a High-Value Credential Process | experimental | high | T1003 T1555 T1555.001 |
| `messages_database_access.yml`<br/>Messages.app Database Accessed by Non-Messages Process | stable | medium | T1005 |
| `network_sniffing.yml`<br/>Network Sniffing Tool Executed | experimental | medium | T1040 |
| `notes_database_access.yml`<br/>Notes.app Database Accessed by Non-Notes Process | experimental | medium | T1005 |
| `pam_module_installed.yml`<br/>PAM Module Installed or Modified | stable | high | T1556.003 |
| `pam_module_tampering.yml`<br/>PAM Module Configuration Tampered | experimental | high | T1556.003 |
| `password_manager_db.yml`<br/>Password Manager Database File Accessed | experimental | medium | T1555.005 |
| `process_reads_other_process_memory_macos.yml`<br/>Process Acquires Read Access to Another Process's Memory (task_read_for_pid) | experimental | medium | T1003 T1057 T1555 |
| `ptrace_attach_to_process.yml`<br/>ptrace Attach to Another Process by Untrusted Tool | experimental | medium | T1003 T1055.008 |
| `safari_history_accessed.yml`<br/>Safari History Database Accessed by Non-Safari Process | experimental | low | T1217 |
| `safari_password_accessed.yml`<br/>Safari Passwords Database Accessed | stable | high | T1555.003 |
| `securityd_memory_access.yml`<br/>securityd Process Memory Access via Mach APIs | experimental | low | T1003 |
| `sensitive_file_read_untrusted.yml`<br/>Untrusted Process Reads macOS Local Directory Service Data | experimental | high | T1003 |
| `shadow_hash_access.yml`<br/>macOS Shadow Hash Plist Access | experimental | high | T1003 |
| `ssh_key_access.yml`<br/>SSH Private Key Accessed by Unusual Process | experimental | medium | T1552.004 |
| `ssh_key_file_read.yml`<br/>SSH Private Key File Accessed | experimental | medium | T1552.004 |
| `ssh_launched_security_dump.yml`<br/>Keychain or Credential Dump over SSH Session | experimental | high | T1003 T1555.001 |
| `tcc_db_access.yml`<br/>TCC Database Direct Access | stable | high | T1562.001 |
| `token_files_accessed.yml`<br/>Cloud Service Token Files Accessed | experimental | medium | T1528 |
| `wifi_password_access.yml`<br/>WiFi Password Extraction via security Command | stable | high | T1555.001 |

### Defense Evasion (TA0005) (69 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `binary_renamed_to_system_utility.yml`<br/>Unsigned Binary Masquerading as System Utility | experimental | medium | T1036.004 |
| `binary_resigned_post_installation.yml`<br/>codesign Re-Sign of Installed Application Bundle | experimental | medium | T1036.001 T1554 |
| `bulk_quarantine_strip.yml`<br/>Bulk Quarantine-Attribute Strip Across Many Files | experimental | medium | T1553.001 T1564.001 |
| `code_signature_invalidated.yml`<br/>Code Signature Invalidated at Runtime | experimental | high | T1553.002 |
| `codesign_remove.yml`<br/>Code Signature Removed from Binary | stable | medium | T1553.002 |
| `csrutil_status_check.yml`<br/>SIP Status Queried via csrutil | experimental | informational | T1518.001 |
| `developer_cert_revoked.yml`<br/>Execution of Binary With Revoked Developer Certificate | experimental | critical | T1553.001 |
| `dyld_injection_runtime.yml`<br/>DYLD_INSERT_LIBRARIES Runtime Injection | stable | medium | T1574.006 |
| `dyld_insert_libraries.yml`<br/>DYLD_INSERT_LIBRARIES Environment Variable Used | stable | medium | T1574.006 |
| `dyld_insert_libraries_env.yml`<br/>DYLD_INSERT_LIBRARIES Set in Process Environment | experimental | medium | T1574.006 |
| `dylib_hijack_writable_path.yml`<br/>Dylib Written to Hijackable Path by Non-Platform Writer | experimental | medium | T1574.004 T1574.006 |
| `dylib_proxying.yml`<br/>install_name_tool Modifying Dylib From User-Writable Path | experimental | low | T1574.004 |
| `env_path_manipulation.yml`<br/>PATH Environment Variable Manipulation in Shell Profiles | experimental | low | T1574.007 |
| `env_var_injection.yml`<br/>Interpreter Search-Path Env Var Set on Non-Platform Process | experimental | low | T1574.007 |
| `fake_apple_bundle_in_user_dir.yml`<br/>Fake Apple Bundle Identifier in User-Writable Location | experimental | high | T1036.004 T1036.005 |
| `file_flag_hidden.yml`<br/>File Hidden via chflags Command | experimental | low | T1564.001 |
| `fileless_attack_indicators.yml`<br/>Fileless Attack Indicators | experimental | medium | T1059.007 T1620 |
| `firewall_disabled.yml`<br/>macOS Application Firewall Disabled | stable | medium | T1562.004 |
| `gatekeeper_disabled.yml`<br/>Gatekeeper Disabled via spctl | stable | critical | T1553.001 |
| `gatekeeper_override.yml`<br/>Gatekeeper Assessment Overridden by User | experimental | high | T1553.001 |
| `gatekeeper_policy_db_modified.yml`<br/>Gatekeeper Policy Database Modified by Non-System Process | experimental | high | T1553.001 T1562.001 |
| `gatekeeper_user_bypass.yml`<br/>User Bypassed Gatekeeper for Blocked Application | deprecated | low | T1204.002 T1553.001 |
| `hidden_file_created.yml`<br/>Hidden File Created in User Directory | experimental | low | T1564.001 |
| `hidden_file_creation_non_home.yml`<br/>Hidden File Created Outside Home Directory | experimental | low | T1564.001 |
| `history_clearing.yml`<br/>Shell History Clearing or Disabling | stable | medium | T1070.003 |
| `info_plist_modification_post_install.yml`<br/>Application Info.plist Modified Post-Installation By Non-Updater | experimental | medium | T1036 T1036.005 |
| `iokit_device_access_unsigned.yml`<br/>Unsigned Process Opens IOKit Device | deprecated | high | T1082 |
| `kernel_cache_rebuild.yml`<br/>Kernel Cache Rebuild by Non-System Process | stable | medium | T1014 |
| `launchservices_cache_tampered.yml`<br/>LaunchServices Assessment Cache Modified by Non-System Process | experimental | medium | T1553.001 |
| `log_deletion.yml`<br/>System Log Files Deleted | stable | high | T1070.002 |
| `maccrab_tamper_attempt.yml`<br/>Attempted Tamper of MacCrab Components (Self-Protection) | experimental | medium | T1070.004 T1562.001 |
| `mas_receipt_access_by_non_sandbox.yml`<br/>Mac App Store Receipt Read By Non-Sandboxed Process | experimental | medium | T1005 T1552.001 |
| `mdm_profile_installed_unexpected.yml`<br/>Unexpected MDM Profile Installation | experimental | medium | T1553.004 T1562.001 |
| `mdm_profile_removal.yml`<br/>MDM Profile Removal Attempt | deprecated | medium | T1562.001 |
| `mdm_profile_removed.yml`<br/>MDM Profile Removal Attempt | experimental | medium | T1562.001 |
| `mount_noexec_bypass.yml`<br/>Mount noexec Flag Manipulation | experimental | medium | T1562.001 T1564.009 |
| `network_extension_unsigned.yml`<br/>Unsigned Network Extension Provider Installation | experimental | high | T1556 |
| `network_extension_unsigned_install.yml`<br/>Network Extension Installed by Unsigned Process | experimental | medium | T1557 |
| `network_policy_plist_tampered.yml`<br/>Network Firewall / Policy Preferences Tampered By Non-Vendor Process | experimental | high | T1562.001 T1562.004 |
| `notarization_absent_non_system.yml`<br/>Non-System Binary Lacks Notarization | stable | low | T1553.001 |
| `nvram_amfi_manipulation.yml`<br/>NVRAM AMFI Security Variable Manipulation | stable | critical | T1562.001 |
| `openssl_decrypt_in_install_lineage.yml`<br/>openssl Decrypt In Package-Install Lineage (Staged Payload Decrypt) | experimental | medium | T1027 T1140 T1195.001 |
| `persona_takeover_fingerprint_drift.yml`<br/>Maintainer git-config Fingerprint Single-Field Drift (Persona Takeover Signal) | experimental | low | T1078 |
| `plutil_binary_to_xml.yml`<br/>plutil Reading Sensitive Plist From Non-Platform Parent | experimental | low | T1562.001 |
| `privacy_preferences_tamper.yml`<br/>Direct Write to Privacy Preferences Plist | stable | high | T1562.001 |
| `process_injection_task_for_pid.yml`<br/>Process Injection via task_for_pid Reference | experimental | low | T1055 |
| `process_suspension.yml`<br/>Process Suspended via SIGSTOP From Non-Platform Parent | experimental | low | T1562.001 |
| `proxy_config_manipulation.yml`<br/>System Proxy Configuration Modified | experimental | medium | T1090 |
| `quarantine_attribute_removed.yml`<br/>Quarantine Attribute Removed from File | stable | medium | T1553.001 |
| `quarantine_database_tampered.yml`<br/>Quarantine Events Database Directly Modified | experimental | high | T1553.001 |
| `quarantine_removed.yml`<br/>Quarantine Extended Attribute Removed from Downloaded File | stable | medium | T1553.001 |
| `remote_thread_injection.yml`<br/>Remote Thread Created in Another Process | experimental | high | T1055 |
| `rosetta_binary_from_downloads.yml`<br/>x86_64 Binary Executed from Downloads or Temp Directory | experimental | medium | T1204.002 |
| `rosetta_unsigned_execution.yml`<br/>Unsigned x86_64 Binary Executed Under Rosetta 2 | experimental | low | T1036 |
| `rosetta_unsigned_x86_binary.yml`<br/>Unsigned x86_64 Binary Execution via Rosetta 2 | experimental | medium | T1204.002 |
| `sandbox_escape_attempt.yml`<br/>sandbox-exec Invoked With Permissive Profile | experimental | medium | T1497.001 |
| `security_tool_killed.yml`<br/>Security Tool Process Terminated | experimental | high | T1562.001 |
| `sip_check_before_tampering.yml`<br/>System Integrity Protection Disable Attempt | stable | medium | T1553.006 |
| `sip_disabled.yml`<br/>System Integrity Protection Disabled | stable | critical | T1562.001 |
| `sip_protected_process_interference.yml`<br/>Attempt to Kill or Signal SIP-Protected Security Process | stable | high | T1562.001 |
| `sudoers_modification.yml`<br/>Sudoers File Modified | experimental | high | T1548.003 |
| `suspicious_xpc_connection.yml`<br/>Unsigned Process Connects to Privileged XPC Service | deprecated | medium | T1559 |
| `task_for_pid_injection.yml`<br/>Mach Port task_for_pid Process Injection | stable | medium | T1055 |
| `tcc_db_direct_write.yml`<br/>Direct TCC Database Modification | experimental | high | T1548 T1562.001 |
| `tcc_reset_attempt.yml`<br/>TCC Database Reset via tccutil | stable | low | T1562.001 |
| `timestomp_touch.yml`<br/>Timestamp Modification via touch Command | experimental | low | T1070.006 |
| `unexpected_apfs_snapshot.yml`<br/>APFS Snapshot Activity Outside Time Machine / Apple Tooling | experimental | low | T1564 |
| `write_below_etc.yml`<br/>Non-System Process Writes to /etc Directory | experimental | medium | T1565.001 |
| `xprotect_disabled.yml`<br/>XProtect or MRT Service Disabled | stable | critical | T1562.001 |

### Discovery (TA0007) (26 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `airport_wifi_scan.yml`<br/>Wi-Fi Network Scanning via airport Utility | experimental | low | T1016 |
| `bluetooth_scanning_tool.yml`<br/>Bluetooth Scanning or Exploitation Tool Detected | experimental | low | T1011.001 |
| `debugger_evasion_check.yml`<br/>Debugger or Analysis Environment Detection Attempt | experimental | low | T1497 T1622 |
| `defaults_read_sensitive.yml`<br/>Defaults Read on Security-Sensitive Domains | experimental | low | T1082 |
| `dscl_user_enumeration.yml`<br/>User Enumeration via dscl | experimental | low | T1033 |
| `edr_remote_session_active.yml`<br/>EDR Remote Action Session Detected | stable | low | T1219 |
| `edr_tool_running.yml`<br/>EDR or Remote Management Tool Running | stable | informational | T1518.001 |
| `insider_threat_tool_running.yml`<br/>Insider Threat or Employee Monitoring Tool Detected | stable | low | T1518.001 |
| `installed_software_discovery.yml`<br/>Installed Software Enumeration via CLI | experimental | low | T1518 T1518.001 |
| `ioreg_hardware_enum.yml`<br/>Hardware Enumeration via ioreg | experimental | low | T1082 |
| `local_group_enumeration.yml`<br/>Local Group Enumeration via dscl or dseditgroup | experimental | low | T1069.001 |
| `locale_check_from_package_lineage.yml`<br/>AppleLanguages / Locale Probe From Package-Manager Lineage (Geofence Skip) | experimental | high | T1195.001 T1480 T1614.001 |
| `lsof_network_enum.yml`<br/>Network Connection Enumeration via lsof by Unsigned Process | experimental | low | T1049 |
| `mdm_enrollment_check.yml`<br/>MDM Enrollment Status Check via profiles | experimental | low | T1082 |
| `mdm_remote_command.yml`<br/>MDM Remote Management Tool Active | stable | low | T1219 |
| `network_interface_enumeration.yml`<br/>Network Interface Enumeration by Unsigned Process | experimental | low | T1016 |
| `password_policy_discovery.yml`<br/>Password Policy Discovery | experimental | low | T1201 |
| `permission_group_discovery.yml`<br/>Local Group and Permission Discovery | experimental | low | T1069 T1069.001 |
| `process_listing_by_unsigned.yml`<br/>Process Listing by Unsigned Process | experimental | low | T1057 |
| `remote_access_tool_running.yml`<br/>Remote Access or Remote Desktop Tool Running | stable | low | T1219 |
| `sensitive_file_search.yml`<br/>Targeted Search for Sensitive Files and Credentials | experimental | medium | T1083 T1552.001 |
| `smbutil_share_enum.yml`<br/>SMB Share Enumeration via smbutil | experimental | low | T1135 |
| `system_enumeration_burst.yml`<br/>System Information Enumeration by Suspicious Process | experimental | low | T1033 T1082 |
| `vm_detection_probe_from_package_lineage.yml`<br/>VM / Sandbox Detection Probe From Package-Manager Lineage | experimental | medium | T1082 T1195.001 T1497.001 |
| `wifi_attack_tool.yml`<br/>Wi-Fi Attack or Reconnaissance Tool Detected | experimental | medium | T1557 |
| `wifi_ssid_change.yml`<br/>Wi-Fi Network SSID Changed or Evil Twin Indicator | experimental | low | T1204 T1204.001 T1557 |

### Execution (TA0002) (34 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `adhoc_signed_app_execution_from_user_dir.yml`<br/>Ad-Hoc Signed Binary Executes From User-Writable Path | experimental | high | T1204.002 T1553.004 |
| `automator_shortcuts_abuse.yml`<br/>Automator Workflow or Shortcuts Executes Shell Commands | experimental | medium | T1059.004 |
| `automator_workflow_from_temp.yml`<br/>Automator Workflow Executed from Temporary Directory | experimental | medium | T1059.002 |
| `base64_decode_execute.yml`<br/>Base64 Decode Piped to Shell Execution | stable | medium | T1027 T1059.004 |
| `binary_executed_from_tmp.yml`<br/>Ad-Hoc or Unsigned Binary Executed from /tmp | experimental | medium | T1204.002 |
| `crypto_miner_process.yml`<br/>Cryptocurrency Miner Process Detected | experimental | high | T1496 |
| `crypto_stratum_protocol.yml`<br/>Stratum Mining Protocol in Command Line | experimental | high | T1496 |
| `curl_wget_download_execute.yml`<br/>curl or wget Download and Pipe to Shell | experimental | medium | T1059.004 T1105 |
| `deep_shell_nesting.yml`<br/>Deep Shell Nesting Detected | experimental | low | T1059.004 |
| `hidden_process_with_network.yml`<br/>Hidden (Dot-Prefixed) Binary Execution | experimental | low | T1564.001 |
| `installer_pkg_postinstall.yml`<br/>PKG Installer Post-Install Script Execution | experimental | medium | T1059.004 |
| `installer_pkg_script_execution.yml`<br/>Installer Package Pre/Post-Install Script Execution | stable | medium | T1059.004 T1204.002 |
| `jxa_execution.yml`<br/>Suspicious JXA (JavaScript for Automation) Invocation | experimental | medium | T1059.007 |
| `launchctl_submit.yml`<br/>launchctl Job Registration or Bootstrap | stable | medium | T1569.001 |
| `malicious_git_hook.yml`<br/>Git Hook Execution from Suspicious Directory | experimental | medium | T1204.002 |
| `mdfind_spotlight_recon.yml`<br/>mdfind Spotlight Query by Unsigned Process | experimental | medium | T1083 |
| `nscript_suspicious.yml`<br/>osascript Loading Script from Mounted Volume or Network URL | experimental | medium | T1059.002 |
| `open_command_url_handler.yml`<br/>macOS `open` Command Invoking Custom or File URL Handler | experimental | low | T1204.001 |
| `osascript_from_non_apple.yml`<br/>osascript Spawned by Non-Apple Parent | experimental | low | T1059.002 |
| `osascript_shell_command.yml`<br/>osascript Executes Shell Command via do shell script | experimental | medium | T1059.002 |
| `pkg_downloads_and_executes.yml`<br/>Installer Script Downloads and Executes Payload | stable | high | T1105 T1204.002 |
| `process_substitution_download.yml`<br/>Download and Execute via Process Substitution | experimental | medium | T1059.004 |
| `python_c_flag_suspicious.yml`<br/>Python One-Liner with Suspicious Imports | stable | low | T1059.006 |
| `python_spawned_by_office_app.yml`<br/>Python or Ruby Spawned by Office Application | experimental | high | T1059 |
| `ruby_perl_from_app.yml`<br/>Ruby or Perl Spawned by Application Bundle | experimental | low | T1059.006 |
| `shell_spawned_by_browser.yml`<br/>Shell Spawned by Browser Process | stable | low | T1059.004 |
| `staged_fetch_then_exec_from_user_writable.yml`<br/>Curl/Wget Fetch Followed By Execution From User-Writable Path | experimental | high | T1105 T1195.001 T1204.002 |
| `suspicious_applescript_inline.yml`<br/>Suspicious Inline AppleScript Execution | experimental | medium | T1059.002 |
| `swift_compile_and_run.yml`<br/>swiftc Invoked From Non-Developer Parent Against /Downloads or /tmp Source | experimental | medium | T1027.004 T1059 |
| `swift_repl_suspicious.yml`<br/>Swift Inline Evaluation From Non-Developer, Non-Terminal Parent | experimental | low | T1059 |
| `terminal_profile_load.yml`<br/>Terminal.app Profile Auto-Runs Shell With Network Download Primitive | experimental | medium | T1059.004 |
| `unsigned_binary_from_downloads.yml`<br/>Unsigned Binary Executed from Downloads | stable | medium | T1204.002 |
| `web_server_deep_spawn.yml`<br/>Web Server Spawns Grandchild Shell Process | experimental | high | T1059.004 T1505.003 |
| `xattr_execute_from_quarantine.yml`<br/>xattr Removes Quarantine on User-Writable Path From Non-Toolchain Parent | experimental | low | T1553.001 |

### Exfiltration (TA0010) (17 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `airdrop_file_transfer.yml`<br/>AirDrop File Transfer by Non-Standard Process | deprecated | informational | T1011.001 |
| `archive_sensitive_dirs.yml`<br/>Archive of Sensitive User Directories | experimental | medium | T1560.001 |
| `base64_large_output.yml`<br/>Base64 Encoding of Files for Exfiltration Staging | experimental | low | T1560.001 |
| `cloud_provider_cli_exfil.yml`<br/>Cloud Provider CLI Used to Upload Data from Sensitive Paths | experimental | medium | T1048 T1567.002 |
| `curl_file_upload.yml`<br/>File Upload via curl Form or Upload Flag | stable | low | T1048.002 |
| `dns_tunneling_large_txt.yml`<br/>Potential DNS Tunneling via Large TXT Queries | experimental | medium | T1048 |
| `exfil_compress_and_stage.yml`<br/>Bulk Archive of Sensitive Directories Before Exfiltration | experimental | medium | T1560.001 |
| `exfil_git_push_sensitive.yml`<br/>Git Push from Sensitive Data Directories | deprecated | low | T1567.003 |
| `exfil_via_email_cli.yml`<br/>Data Exfiltration via CLI Mail Tools | experimental | medium | T1048 |
| `exfil_via_ftp.yml`<br/>FTP/SFTP Outbound Data Transfer to External Host | experimental | medium | T1048.002 |
| `exfil_webhook_post.yml`<br/>Potential Data Exfiltration via Webhook POST | experimental | medium | T1567.001 |
| `icmp_tunnel_exfil.yml`<br/>ICMP Tunneling Tool Execution | experimental | high | T1048.002 T1572 |
| `messaging_api_data_upload.yml`<br/>Data Upload to Messaging Platform API | experimental | medium | T1102 T1567.004 |
| `paste_service_upload.yml`<br/>Data Posted to Public Paste or File Sharing Service | experimental | medium | T1102.001 T1567 |
| `rclone_cloud_exfil.yml`<br/>rclone Used for Cloud Storage Exfiltration | experimental | medium | T1567.002 |
| `rsync_to_external.yml`<br/>Rsync to External Destination from Sensitive Directories | experimental | medium | T1048.002 |
| `scp_outbound_sensitive.yml`<br/>SCP Outbound Copy from Sensitive Directories | stable | medium | T1048.002 |

### Impact (TA0040) (16 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `audit_log_tampering.yml`<br/>System Audit Log or Unified Log Tampered | experimental | high | T1070.002 |
| `browser_data_destruction.yml`<br/>Browser Profile or History Bulk Deleted | experimental | medium | T1070.004 |
| `cryptominer_execution.yml`<br/>Cryptomining Software Executed | experimental | high | T1496 |
| `data_encoding_destruction.yml`<br/>File Overwritten with Random or Zero Bytes Before Deletion | experimental | medium | T1070.004 T1485 |
| `disk_wipe_command.yml`<br/>Disk Wipe or Overwrite Command | experimental | critical | T1485 |
| `firmware_tamper.yml`<br/>EFI or Firmware Update Tool Executed by Non-System Process | experimental | high | T1542.001 T1542.003 |
| `forced_system_shutdown.yml`<br/>Forced System Shutdown or Reboot from Shell | experimental | low | T1529 |
| `hosts_file_modification.yml`<br/>System Hosts File Modified | experimental | medium | T1565.001 |
| `inhibit_system_recovery.yml`<br/>System Recovery Inhibited | experimental | high | T1490 |
| `known_macos_ransomware.yml`<br/>Known macOS Ransomware Process Detected | experimental | critical | T1486 |
| `mass_file_deletion.yml`<br/>Mass File Deletion from Critical Directories | experimental | medium | T1485 |
| `mass_file_encryption.yml`<br/>Mass File Encryption Pattern Detected | experimental | medium | T1486 |
| `mass_unlink_from_package_lineage.yml`<br/>Recursive Unlink Targeting $HOME From Package-Manager Lineage | experimental | high | T1070.004 T1195.001 T1485 |
| `ransomware_note_created.yml`<br/>Ransomware Note or Encrypted Extension File Created | experimental | high | T1486 |
| `security_tool_disabled.yml`<br/>macOS Security Feature Disabled via Command Line | experimental | high | T1562.001 |
| `service_stop.yml`<br/>macOS System Service Stopped via launchctl bootout | experimental | high | T1489 |

### Initial Access (TA0001) (13 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `app_translocation_execution.yml`<br/>Application Executed from App Translocation Path | experimental | medium | T1204.002 |
| `calendar_ics_handler.yml`<br/>Calendar Invitation Handler Spawning Processes | experimental | medium | T1566.001 |
| `database_server_spawns_shell.yml`<br/>Database Server Spawns Shell or Scripting Interpreter | experimental | medium | T1059 T1190 |
| `dmg_mounted_from_suspicious_location.yml`<br/>DMG Mounted from User-Writable Staging Path | experimental | low | T1204.002 |
| `fake_keychain_dialog_from_install_lineage.yml`<br/>osascript Fake Keychain / iCloud Password Dialog From Package-Install Lineage (OpenClaw) | experimental | high | T1056.002 T1059.002 T1195.001 T1555 |
| `iso_mounted_from_download.yml`<br/>ISO or DMG Mounted from Downloads Directory | experimental | medium | T1204.002 |
| `network_service_writes_webshell.yml`<br/>Network Service Writes Potential Web Shell File | experimental | medium | T1190 T1505.003 |
| `office_macro_execution.yml`<br/>Microsoft Office Spawning Macro-Related Processes | stable | high | T1204.002 T1566.001 |
| `sshd_spawns_unusual_child.yml`<br/>sshd Spawns Unusual Child Process | experimental | medium | T1190 |
| `url_scheme_handler_collision.yml`<br/>URL-Scheme Handler Registered To Non-Canonical App | experimental | medium | T1547.015 |
| `url_scheme_hijack.yml`<br/>Custom URL Scheme Handler Registered | experimental | low | T1036 |
| `web_server_spawns_reverse_shell.yml`<br/>Web Server Spawns Reverse Shell or Download Utility | experimental | medium | T1190 |
| `web_server_spawns_shell.yml`<br/>Web Server Process Spawns Shell Interpreter | experimental | high | T1190 T1505.003 |

### Lateral Movement (TA0008) (18 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `airplay_to_non_apple_device.yml`<br/>Third-Party AirPlay Receiver or Sender Binary Executed | experimental | low | T1125 |
| `apple_remote_desktop.yml`<br/>Apple Remote Desktop Management Activation | stable | medium | T1021 |
| `bonjour_mdns_host_discovery.yml`<br/>Bonjour/mDNS Host Discovery by Unexpected Process | experimental | low | T1046 T1135 |
| `directory_service_user_enumeration.yml`<br/>Active Directory or Local User Enumeration via dscl or ldapsearch | experimental | low | T1069.002 T1087.002 |
| `insecure_remote_protocol.yml`<br/>Insecure Remote Protocol Usage (telnet, rsh, rlogin, rexec) | experimental | medium | T1021 |
| `known_hosts_modification.yml`<br/>SSH known_hosts File Modified by Non-SSH Process | experimental | medium | T1021.004 T1557 |
| `mass_ssh_from_single_process.yml`<br/>Suspicious SSH from Script-like or Non-Interactive Parent | experimental | low | T1021.004 T1570 |
| `mosh_lateral_movement.yml`<br/>Mosh (Mobile Shell) Remote Session from Unsigned Process | experimental | low | T1021.004 |
| `network_share_mounted_by_unsigned.yml`<br/>Network File Share Mounted by Unsigned Process | experimental | low | T1021.002 |
| `osascript_via_ssh.yml`<br/>Remote AppleScript/JXA Execution via SSH | experimental | medium | T1021.004 T1059.002 |
| `rdp_protocol_open.yml`<br/>Remote Desktop Connection Initiated via open Command or Non-Standard App | experimental | low | T1021.001 T1021.005 |
| `rsync_over_ssh_to_internal.yml`<br/>rsync File Sync to Internal Host via SSH by Unsigned Process | experimental | low | T1021.004 T1570 |
| `screensharing_enabled_by_process.yml`<br/>Screen Sharing or Remote Desktop Enabled Programmatically | experimental | medium | T1021.001 T1021.005 |
| `ssh_agent_hijacking.yml`<br/>SSH Agent Socket Access by Unexpected Process | experimental | medium | T1021.004 T1563.001 |
| `ssh_forwarding_chain.yml`<br/>SSH Port Forwarding or ProxyJump from Unsigned Process | experimental | low | T1021.004 T1572 |
| `ssh_to_internal_from_unsigned.yml`<br/>SSH to Internal Network from Unsigned Process | experimental | low | T1021.004 |
| `stolen_ssh_key_usage.yml`<br/>SSH Key Used from Non-Standard or Temporary Location | experimental | medium | T1021.004 T1552.004 |
| `vnc_server_started.yml`<br/>VNC Server Started or Screen Sharing Activated | stable | medium | T1021.005 |

### Persistence (TA0003) (39 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `accessibility_bundle_loaded.yml`<br/>Accessibility Bundle Loaded from Unusual Path | experimental | medium | T1547 |
| `adhoc_signed_launchagent_write.yml`<br/>Ad-Hoc Signed Binary Writes a LaunchAgent or LaunchDaemon | experimental | high | T1543.001 T1543.004 |
| `app_installed_outside_applications.yml`<br/>Application Bundle Staged in Suspicious Path | experimental | medium | T1036.005 |
| `at_job_creation.yml`<br/>At Job Scheduled (Legacy macOS Scheduler) | experimental | medium | T1053.002 |
| `authorization_plugin_installed.yml`<br/>Authorization Plugin Installed | stable | high | T1547.002 |
| `browser_extension_installed.yml`<br/>Browser Extension Installed by Non-Browser Process | experimental | medium | T1176 |
| `cron_job_created.yml`<br/>Cron Job Created by Non-Crontab Process | experimental | medium | T1053.003 |
| `directory_service_plugin.yml`<br/>Directory Service Plugin Installed | stable | high | T1556 |
| `dock_persistence_entry_written.yml`<br/>Dock Persistence Entry Written via defaults | experimental | low | T1547 |
| `dock_tile_plugin.yml`<br/>Dock Tile Plugin Installed | experimental | medium | T1547 |
| `emond_rule_created.yml`<br/>Event Monitor Daemon Rule Created | stable | high | T1546 |
| `finder_sync_extension.yml`<br/>Finder Sync Extension Installed by Unsigned Process | experimental | medium | T1547 |
| `folder_actions_abuse.yml`<br/>Folder Actions Script Installed for Persistence | experimental | medium | T1547.015 |
| `gh_token_monitor_plist_dropped.yml`<br/>TanStack gh-token-monitor LaunchAgent Plist Dropped (Dead-Man's-Switch Watchdog) | experimental | critical | T1195.001 T1485 T1543.001 |
| `honeyfile_accessed.yml`<br/>Deception Honeyfile Accessed | stable | high | T1083 T1552.001 |
| `kext_loaded.yml`<br/>Kernel Extension Loaded | deprecated | informational | T1547.006 |
| `launch_agent_created_by_unsigned.yml`<br/>LaunchAgent Created by Unsigned Process | stable | high | T1543.001 |
| `launch_agent_user_created.yml`<br/>User LaunchAgent Created by Non-Installer Parent | experimental | high | T1543.001 |
| `launch_daemon_created.yml`<br/>LaunchDaemon Created | stable | medium | T1543.004 |
| `launchagent_with_distant_future_trigger.yml`<br/>LaunchAgent Plist With Distant Future Trigger (Time-Bomb Persistence) | experimental | medium | T1029 T1543.001 |
| `launchd_override_created.yml`<br/>LaunchDaemon Override Database Modified | stable | medium | T1543.004 |
| `login_item_added_from_tmp.yml`<br/>Login Item Added from Temporary Directory | stable | high | T1547.015 |
| `loginhook_set.yml`<br/>Login or Logout Hook Configured via defaults | stable | medium | T1037.002 |
| `maintainer_publish_hour_anomaly.yml`<br/>Package Publish From Non-Interactive Parent (Drift-Detection Input) | experimental | low | T1078 |
| `notification_center_plugin.yml`<br/>Notification Center Widget Plugin Installed (Legacy) | experimental | informational | T1547 |
| `periodic_script_created.yml`<br/>Periodic Script Created | stable | medium | T1053.003 |
| `plist_written_to_library.yml`<br/>Plist Written to Library by Process from Temp Directory | stable | high | T1543.001 |
| `quicklook_plugin_installed.yml`<br/>QuickLook Plugin Installed | experimental | medium | T1547 |
| `quicklook_spotlight_plugin.yml`<br/>Malicious Quick Look or Spotlight Plugin Installed | experimental | medium | T1547 |
| `rogue_xpc_service.yml`<br/>Non-Standard XPC Service Registered | experimental | low | T1543 |
| `shell_profile_modification.yml`<br/>Shell Profile Modified by Non-Shell Process | experimental | low | T1546.004 |
| `spotlight_importer_installed.yml`<br/>Spotlight Importer Plugin Installed | experimental | medium | T1547 |
| `spotlight_importer_unsigned.yml`<br/>Unsigned Spotlight mdimporter Plugin Installed | stable | medium | T1547 |
| `startup_script_etc_rc.yml`<br/>Startup Script Created in /etc/rc.d or /etc/rc.local | stable | medium | T1037.004 |
| `system_extension_loaded.yml`<br/>System Extension Loaded (Modern Persistence) | experimental | medium | T1547.006 |
| `system_launchdaemon_plist_replaced.yml`<br/>System LaunchDaemon Plist Replaced | experimental | critical | T1543.004 |
| `systemextension_installed.yml`<br/>System Extension Installed by Non-Apple Process | experimental | medium | T1547.006 |
| `xpc_service_registered.yml`<br/>XPC Service Dynamically Registered | experimental | medium | T1543.001 |
| `xpc_service_replacement.yml`<br/>XPC Service Replacement by Unsigned Process | experimental | high | T1543.004 |

### Privilege Escalation (TA0004) (21 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `authorizationdb_modify.yml`<br/>Authorization Database Modified via security Command | stable | high | T1548 |
| `dscl_password_change.yml`<br/>Password Change via dscl Command | stable | medium | T1098 |
| `exploit_payload_in_tmp.yml`<br/>Unsigned Binary Execution from /tmp with Elevated Privileges | experimental | high | T1068 |
| `kernel_exploit_crash_indicator.yml`<br/>Crash Reporter Invoked Against Kernel or Privileged Subsystem (Precursor) | experimental | low | T1068 |
| `mach_port_exploitation.yml`<br/>Mach Port Manipulation for Process Injection | experimental | medium | T1055 |
| `pkexec_equivalent.yml`<br/>AuthorizationExecuteWithPrivileges Pattern Detected | experimental | medium | T1548.004 |
| `platform_binary_dylib_injection.yml`<br/>Platform Binary Loads Unsigned Code via Tcl/Dylib Injection | experimental | medium | T1574.006 |
| `platform_binary_stdin_injection.yml`<br/>Platform Binary Receives Piped Input from Suspicious Source | experimental | low | T1059 |
| `sandbox_escape_indicators.yml`<br/>App Sandbox Escape Indicators (DEPRECATED — unsalvageable) | deprecated | informational | T1611 |
| `setuid_setgid_modification.yml`<br/>SetUID or SetGID Bit Modified on File | experimental | medium | T1548.001 |
| `sudo_from_suspicious_parent.yml`<br/>sudo Executed from Suspicious Parent Process | experimental | low | T1548.003 |
| `suid_binary_created.yml`<br/>SUID/SGID Binary Created in Suspicious Directory | experimental | medium | T1068 T1548.001 |
| `suspicious_mach_port_access.yml`<br/>Suspicious Mach Port Exploitation Primitives in Command Line | experimental | medium | T1068 |
| `symlink_over_sensitive_file.yml`<br/>Symlink Created Targeting Sensitive System File | experimental | medium | T1548 |
| `symlink_race_tmp.yml`<br/>Symlink in Tmp Directory Pointing Outside Tmp | experimental | low | T1548 |
| `synthetic_click_tcc_bypass.yml`<br/>Synthetic Click or Accessibility API Abuse | experimental | medium | T1056 T1548 |
| `tcc_bypass_via_injection.yml`<br/>TCC Bypass via Process Injection into Protected App Bundle | experimental | high | T1068 |
| `tcc_database_manipulation.yml`<br/>TCC Database Direct SQLite Manipulation | experimental | high | T1548 |
| `tcc_full_disk_via_ssh.yml`<br/>SSH Session Accessing FDA-Protected Paths | stable | medium | T1548 |
| `xpc_service_enumeration.yml`<br/>Privileged XPC Service Enumeration (Discovery Precursor) | experimental | low | T1057 T1559 |
| `xpc_service_exploit_pattern.yml`<br/>Unsigned Process Connects to Privileged XPC Service | experimental | medium | T1548 T1559 |

### Supply Chain (Sigma) (53 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `ai_tool_config_accessed_by_unknown.yml`<br/>AI Tool Configuration Accessed by Non-AI Process | experimental | medium | T1195.001 T1552.001 |
| `axios_rat_macos_payload.yml`<br/>Axios RAT macOS Payload Created | experimental | critical | T1036.005 T1195.001 T1543 |
| `bun_executes_from_node_modules.yml`<br/>Bun Runtime Executes From node_modules (Mini Shai-Hulud Evasion) | experimental | medium | T1027 T1059 T1195.001 |
| `cloud_metadata_imds_query.yml`<br/>Cloud Instance Metadata Service (IMDS) Query | experimental | medium | T1552.005 T1580 |
| `dead_mans_switch_literal_scanner.yml`<br/>Dead-Man's-Switch Wiper Token Literal Observed | experimental | critical | T1195.001 T1485 |
| `developer_credential_bulk_harvest.yml`<br/>Developer Credential File Read By Untrusted Process (DEPRECATED — count not enforceable) | deprecated | informational | T1195.001 T1552 T1552.001 T1552.004 |
| `git_credential_accessed_by_non_git.yml`<br/>Git Credential Files Accessed by Unexpected Process | experimental | medium | T1195.001 T1552.001 |
| `github_user_repos_post_from_non_git.yml`<br/>api.github.com /user/repos POST From Non-Git Client (Dead-Drop Repo Creation) | experimental | medium | T1195.001 T1552 T1567 |
| `glassworm_persistence_init_json.yml`<br/>GlassWorm Persistence via init.json in Home Directory | experimental | high | T1195.001 T1547 |
| `hidden_vnc_socks_proxy.yml`<br/>Hidden VNC or SOCKS Proxy Server Started by Non-System Process | experimental | medium | T1090 T1195.001 T1219 |
| `homebrew_formula_no_check_sha.yml`<br/>Homebrew Formula Installed Without SHA Verification (:no_check) | experimental | medium | T1195.002 |
| `homebrew_tap_mitm_cleartext_http.yml`<br/>Homebrew Process Fetches Over Cleartext HTTP (Tap MITM) | experimental | medium | T1195.002 T1557 |
| `lockfile_unexpected_modification.yml`<br/>Package Lockfile Modified Outside Package Manager | experimental | medium | T1195.002 |
| `node_ipc_compromised_versions.yml`<br/>Compromised node-ipc Version Observed in node_modules (peacenotwar 9.1.6/9.2.3/12.0.1) | experimental | high | T1059.007 T1195.001 T1485 |
| `node_modules_contains_leaked_dotfile.yml`<br/>Leaked Dotfile / Secret Material Under node_modules After Install | experimental | medium | T1195.001 T1552.001 |
| `node_modules_spawns_binary.yml`<br/>Binary Executed Directly from node_modules Directory | experimental | low | T1059.007 T1195.001 |
| `node_process_writes_to_system_dirs.yml`<br/>Node.js Process Writes to System Directories | experimental | medium | T1036.005 T1059.007 T1195.001 |
| `npm_install_from_ai_tool.yml`<br/>npm Install Command Spawned by AI Coding Tool | experimental | low | T1195.001 T1204.002 |
| `npm_postinstall_downloads_binary.yml`<br/>NPM Postinstall Downloads External Binary | experimental | medium | T1059.004 T1105 T1195.001 |
| `npm_postinstall_spawns_shell.yml`<br/>NPM Postinstall Script Spawns Shell Process | experimental | low | T1059.004 T1195.001 |
| `npm_publish_from_ci.yml`<br/>npm Publish Executed from Unusual Context | experimental | medium | T1059.004 T1195.001 |
| `npm_publish_self_propagation.yml`<br/>npm publish Spawned by Non-Interactive Parent (Worm Self-Propagation) | experimental | high | T1098 T1195.001 |
| `npm_token_accessed_by_non_npm.yml`<br/>npm Auth Token Accessed by Non-npm Process | experimental | high | T1195.001 T1552.001 |
| `npmrc_pypirc_modified_by_non_package_manager.yml`<br/>Package-Manager Config File Modified by Non-Package-Manager Process | experimental | medium | T1195.002 T1565.001 |
| `obfuscator_signature_in_package_payload.yml`<br/>Obfuscator-Style Signature in Newly-Installed Package File | experimental | medium | T1027 T1195.001 |
| `package_drops_native_binary_in_pure_js_pkg.yml`<br/>Native Binary Dropped Under node_modules Without binding.gyp (Smuggled Mach-O) | experimental | medium | T1105 T1195.001 |
| `package_install_drops_github_workflow.yml`<br/>Package-Install Lineage Writes a GitHub Actions Workflow | experimental | high | T1195.001 T1546 |
| `package_manager_downloads_and_executes.yml`<br/>Package Manager Spawns Download Tool Followed by Execution | experimental | high | T1059.004 T1105 T1195.001 |
| `package_manager_downloads_bun_runtime.yml`<br/>Package-Install Lineage Downloads Bun Runtime via curl/wget (Mini Shai-Hulud) | experimental | high | T1027 T1105 T1195.001 |
| `package_postinstall_fetches_alt_runtime.yml`<br/>Package Postinstall Lineage Fetches Bun / Deno / Node Runtime Binary | experimental | medium | T1027 T1105 T1195.001 |
| `package_runtime_drop_evasion.yml`<br/>Package-Manager Descendant Drops Alt JS/Python Runtime (Evasion) | experimental | medium | T1027 T1105 T1195.001 |
| `pip_install_from_ai_tool.yml`<br/>pip Install Command Spawned by AI Coding Tool | experimental | low | T1195.001 T1204.002 |
| `pip_install_triggers_credential_harvest.yml`<br/>pip or Python Process Accesses Sensitive Credential Store | experimental | medium | T1195.001 T1552 |
| `pip_install_with_extra_index_url_to_public_pypi.yml`<br/>pip Install Uses --extra-index-url Alongside Public PyPI (Dependency Confusion Risk) | experimental | low | T1195.002 |
| `pip_package_writes_outside_site_packages.yml`<br/>pip Install Process Writes Outside site-packages | experimental | medium | T1059.006 T1195.001 T1546 |
| `pip_wheel_drops_javascript_runtime_files.yml`<br/>pip-Installed Wheel Drops JavaScript / Bun Runtime Files (Cross-Ecosystem Smuggle) | experimental | critical | T1027 T1195.001 |
| `postinstall_script_persistence.yml`<br/>Package Install Process Creates Persistence Mechanism | experimental | medium | T1053.003 T1195.001 T1543.001 |
| `process_scans_for_llm_tools.yml`<br/>Unexpected Process Reads AI/LLM Tool Configuration | experimental | low | T1083 T1195.001 T1552.001 |
| `pypi_twine_upload_from_non_interactive.yml`<br/>twine upload Spawned by Non-Interactive Parent (PyPI Worm Propagation) | experimental | medium | T1098 T1195.001 |
| `python_process_reads_cloud_credentials.yml`<br/>Python Process Reads Cloud Provider Credentials | experimental | medium | T1195.001 T1552.001 |
| `python_process_reads_env_files.yml`<br/>Python Process Reads .env Files Outside Project Directory | experimental | low | T1195.001 T1552.001 |
| `python_process_reads_k8s_config.yml`<br/>Python Process Reads Kubernetes Configuration | experimental | medium | T1195.001 T1552.001 |
| `python_process_reads_ssh_keys.yml`<br/>Python Process Reads SSH Private Keys | experimental | medium | T1195.001 T1552.004 |
| `python_pth_file_created.yml`<br/>Python .pth File Created in Site-Packages | experimental | medium | T1195.001 T1546 |
| `registry_oidc_token_exchange_from_non_interactive.yml`<br/>npm Registry OIDC Token Exchange From Non-Interactive Parent | experimental | medium | T1098 T1195.001 |
| `suspicious_binary_in_library_caches.yml`<br/>Non-Apple Binary Created in Library Caches Masquerading as Apple | experimental | high | T1036.005 T1543 |
| `suspicious_vscode_extension_network.yml`<br/>VS Code Extension Makes Suspicious Outbound Connection | experimental | low | T1071 T1195.001 |
| `unexpected_node_installation.yml`<br/>Unexpected Node.js Installation in Home Directory | experimental | medium | T1059.007 T1105 T1195.001 |
| `urgency_lexicon_in_install_lineage_pr.yml`<br/>Urgency-Lexicon Markers In Package-Install Lineage Content | experimental | low | T1566 |
| `vscode_extension_spawns_shell.yml`<br/>VS Code Extension Host Spawns Shell Outside Workspace | experimental | low | T1059.004 T1195.001 |
| `vscode_extension_steals_credentials.yml`<br/>VS Code Process Reads Developer Credential Files | experimental | medium | T1195.001 T1552.001 |
| `webhook_exfil_url_in_install_content.yml`<br/>Known Exfil Endpoint URL in Installed Package Content | experimental | high | T1102 T1195.001 T1567 |
| `workflow_drop_with_self_hosted_runner.yml`<br/>GitHub Actions Workflow With self-hosted Runner Dropped by Package Install (TanStack) | experimental | high | T1078.004 T1195.001 T1546 |

### TCC / macOS Privacy (8 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `accessibility_granted_to_unsigned.yml`<br/>Accessibility Permission Granted to Unsigned Application | stable | medium | T1056.001 |
| `camera_access_granted.yml`<br/>Camera TCC Permission Granted to Non-Standard Application | experimental | low | T1125 |
| `contacts_access_granted.yml`<br/>Contacts TCC Permission Granted to Unsigned Application | experimental | low | T1560 |
| `fda_granted_to_unsigned.yml`<br/>Full Disk Access Granted to Unsigned Application | stable | medium | T1562.001 |
| `input_monitoring_granted.yml`<br/>Input Monitoring TCC Permission Granted | stable | medium | T1056 |
| `microphone_access_granted.yml`<br/>Microphone TCC Permission Granted to Non-Standard Application | experimental | low | T1123 |
| `photos_access_granted.yml`<br/>Photos Library TCC Permission Granted to Unsigned Application | experimental | low | T1005 |
| `screen_recording_granted.yml`<br/>Screen Recording Permission Granted | experimental | low | T1113 |

### Wireless / RF (8 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `ble_covert_channel.yml`<br/>Bluetooth Low Energy Covert Channel or Exfiltration Tool | experimental | medium | T1011 |
| `bluetooth_attack_tool.yml`<br/>Bluetooth Attack or Scanning Tool Executed | experimental | medium | T1557 |
| `pmkid_wpa_handshake_capture.yml`<br/>WPA Handshake or PMKID Capture Attempt | experimental | medium | T1040 |
| `rogue_hotspot_creation.yml`<br/>Rogue Software Hotspot or Internet Sharing Enabled Programmatically | experimental | medium | T1557 |
| `wifi_config_file_written.yml`<br/>Wi-Fi Preference File Modified by Non-System Process | experimental | medium | T1565.001 |
| `wifi_deauth_injection.yml`<br/>Wi-Fi Deauthentication Frame Injection Detected | experimental | medium | T1498 |
| `wifi_password_extraction.yml`<br/>Wi-Fi Password Extracted from Keychain | experimental | high | T1555.001 |
| `wifi_profile_manipulation.yml`<br/>Wi-Fi Network Profile Added or Removed by Unsigned Process | experimental | medium | T1557 T1565.002 |

### Sequence Rules (multi-step) (41 rules)

| Rule | Status | Severity | MITRE Techniques |
|---|---|---|---|
| `ai_credential_fence_breach.yml`<br/>AI Tool Reads Credentials Then Makes Network Connection | experimental | high | T1071 T1552 |
| `ai_tool_slopsquatting_install.yml`<br/>AI Coding Tool Triggers Package Install with Suspicious Outcome | experimental | medium | T1059 T1195.001 |
| `archive_to_cloud_exfil.yml`<br/>Sensitive File Archive Followed by Cloud Upload | experimental | high | T1560.001 T1567.002 |
| `browser_exploit_chain.yml`<br/>Browser Exploitation to Shell to Payload | experimental | high | T1059.004 T1189 |
| `browser_extension_data_theft.yml`<br/>Malicious Browser Extension Reads Cookies Then Exfiltrates | experimental | medium | T1185 T1539 |
| `clipboard_hijack_then_exfil.yml`<br/>Clipboard Content Captured Then Sent to External Server | experimental | high | T1115 |
| `container_escape_to_host.yml`<br/>Container Process Writes to Host Filesystem Then Persists | experimental | high | T1547 T1611 |
| `credential_theft_exfil.yml`<br/>Credential File Access Followed by Network Upload | experimental | high | T1041 T1555 |
| `cron_install_then_exec.yml`<br/>Crontab/At Job Installation Followed by Execution | experimental | medium | T1053.003 T1059 |
| `defense_evasion_kill_persist.yml`<br/>Security Tool Killed Then Persistence Installed | stable | high | T1543.001 T1562.001 |
| `discovery_cred_exfil.yml`<br/>Discovery to Credential Access to Exfiltration | experimental | medium | T1082 T1555.001 |
| `dmg_mount_unsigned_exec.yml`<br/>DMG Mount Followed by Unsigned Binary Execution | experimental | medium | T1204.002 |
| `download_persist_c2.yml`<br/>Download to Persistence to C2 Attack Chain | experimental | high | T1071.001 T1543.001 |
| `download_then_cryptominer.yml`<br/>File Download Followed by Cryptominer Execution | experimental | high | T1105 T1496 |
| `dropper_execution_cleanup.yml`<br/>Dropper Execution with Self-Cleanup | experimental | medium | T1070.004 |
| `gh_token_revocation_polling_loop.yml`<br/>Package-Install Lineage Followed by Sustained api.github.com Polling (TanStack Dead-Man's-Switch) | experimental | high | T1071.001 T1195.001 T1485 |
| `installer_pkg_persistence.yml`<br/>Installer Package Drops Persistence | experimental | medium | T1543.001 |
| `keylogger_install_and_persist.yml`<br/>CGEvent Tap Installed Then Persistence Written | experimental | high | T1056.001 T1547.011 |
| `lateral_ssh_persist.yml`<br/>SSH Connection Followed by Persistence on Remote Host Indicators | experimental | medium | T1021.004 |
| `llm_api_key_harvest_exfil.yml`<br/>LLM Tool Config Scan Followed by Credential Exfiltration | experimental | high | T1041 T1195.001 T1552.001 |
| `notarized_dropper_pattern.yml`<br/>Notarized Binary Drops and Executes Unnotarized Payload | experimental | medium | T1105 T1553.001 |
| `npm_module_require_then_bulk_credential_read.yml`<br/>node Process Reads Multiple Credential Files Shortly After /node_modules/ Spawn (node-ipc / require-time) | experimental | high | T1059.007 T1195.001 T1552 T1555 |
| `npm_postinstall_to_rat.yml`<br/>npm Postinstall Drops and Executes RAT (Axios-style) | stable | high | T1059.004 T1195.001 |
| `osascript_download_execute.yml`<br/>AppleScript Downloads and Executes Payload | experimental | high | T1059.002 T1105 |
| `package_typosquat_full_chain.yml`<br/>Typosquatted Package Install Calls Home and Drops Persistence | experimental | high | T1195.001 |
| `phishing_attachment_exec.yml`<br/>Phishing Attachment Opens Then Spawns Shell or Downloader | experimental | high | T1059 T1566.001 |
| `pip_install_to_credential_harvest.yml`<br/>pip Install Triggers Credential Harvesting (LiteLLM-style) | stable | high | T1195.001 T1552.001 |
| `privesc_to_persistence.yml`<br/>Privilege Escalation Followed by Persistence Installation | experimental | medium | T1543.004 T1548.003 |
| `quarantine_remove_execute.yml`<br/>Quarantine Removal Followed by Execution | stable | medium | T1553.001 |
| `ransomware_kill_chain.yml`<br/>Ransomware Kill Chain — Recovery Inhibition Then Data Destruction | experimental | critical | T1485 T1486 T1490 |
| `reverse_shell_chain.yml`<br/>Shell Spawn to Reverse Shell Connection | stable | medium | T1059.004 |
| `rosetta_download_execute_c2.yml`<br/>Rosetta 2 Download-Execute-C2 Chain | experimental | high | — |
| `screenshot_then_exfil.yml`<br/>Screen Capture Followed by Data Upload | experimental | medium | T1041 T1113 |
| `ssh_lateral_tool_transfer.yml`<br/>SSH Session Transfers Tool Then Executes It | experimental | medium | T1021.004 T1105 |
| `supply_chain_full_kill_chain.yml`<br/>Full Supply Chain Kill Chain - Install to Persist to Exfiltrate | experimental | high | T1195.001 T1543.001 T1552.001 |
| `tcc_grant_then_abuse.yml`<br/>TCC Permission Grant Followed by Sensitive Access (Same Lineage) | experimental | medium | T1562.001 |
| `tempest_prep_chain.yml`<br/>TEMPEST Preparation Chain — SDR Connect then Outbound Data Transfer | experimental | low | T1048 T1125 |
| `usb_drop_then_exec.yml`<br/>File Dropped from Removable Media Then Executed | experimental | medium | T1059 T1091 |
| `vscode_extension_to_credential_theft.yml`<br/>VS Code Extension Steals Credentials and Establishes C2 (GlassWorm-style) | experimental | high | T1195.001 T1552.001 |
| `worm_self_propagation_signal.yml`<br/>Worm Self-Propagation Signal (Shai-Hulud / Lightning Pattern) | experimental | high | T1098 T1195.001 T1555 T1567 |
| `xcode_supply_chain.yml`<br/>Xcode Build Spawns Unexpected Network Connection | experimental | low | T1195.001 |

## Full MITRE ATT&CK technique list

All technique IDs referenced anywhere in the rule corpus:

| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1003 | T1003.007 | T1005 | T1011 | T1011.001 | T1014 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1016 | T1021 | T1021.001 | T1021.002 | T1021.004 | T1021.005 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1027 | T1027.004 | T1029 | T1033 | T1036 | T1036.001 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1036.004 | T1036.005 | T1037.002 | T1037.004 | T1040 | T1041 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1046 | T1048 | T1048.002 | T1048.003 | T1049 | T1053.002 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1053.003 | T1055 | T1055.008 | T1056 | T1056.001 | T1056.002 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1057 | T1059 | T1059.002 | T1059.004 | T1059.006 | T1059.007 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1068 | T1069 | T1069.001 | T1069.002 | T1070.002 | T1070.003 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1070.004 | T1070.006 | T1071 | T1071.001 | T1071.004 | T1078 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1078.004 | T1082 | T1083 | T1087.002 | T1090 | T1090.003 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1091 | T1095 | T1098 | T1102 | T1102.001 | T1105 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1110 | T1113 | T1114.001 | T1115 | T1123 | T1125 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1135 | T1140 | T1176 | T1185 | T1189 | T1190 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1195 | T1195.001 | T1195.002 | T1200 | T1201 | T1204 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1204.001 | T1204.002 | T1217 | T1219 | T1480 | T1485 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1486 | T1489 | T1490 | T1496 | T1497 | T1497.001 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1498 | T1505.003 | T1518 | T1518.001 | T1528 | T1529 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1539 | T1542.001 | T1542.003 | T1543 | T1543.001 | T1543.004 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1546 | T1546.004 | T1546.016 | T1547 | T1547.002 | T1547.006 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1547.011 | T1547.015 | T1548 | T1548.001 | T1548.003 | T1548.004 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1552 | T1552.001 | T1552.004 | T1552.005 | T1552.007 | T1553.001 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1553.002 | T1553.004 | T1553.006 | T1554 | T1555 | T1555.001 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1555.003 | T1555.005 | T1556 | T1556.003 | T1557 | T1559 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1560 | T1560.001 | T1562.001 | T1562.004 | T1563.001 | T1564 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1564.001 | T1564.009 | T1565.001 | T1565.002 | T1566 | T1566.001 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1567 | T1567.001 | T1567.002 | T1567.003 | T1567.004 | T1568.002 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1569.001 | T1570 | T1571 | T1572 | T1574.004 | T1574.006 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1574.007 | T1580 | T1609 | T1610 | T1611 | T1614.001 |
| Technique | Technique | Technique | Technique | Technique | Technique |
| --- | --- | --- | --- | --- | --- |
| T1620 | T1622 | | | | |

## How to read this

- **Rule** column: filename + the rule's declared title.
- **Status** column: `experimental` (still tuning), `stable`
  (production-ready by alpha standards), `deprecated`
  (will be removed; do not enable).
- **Severity**: critical / high / medium / low /
  informational. Drives notification routing + dashboard
  ordering. See `docs/MODULES.md` for the rule engine's
  maturity rating.
- **MITRE Techniques**: technique IDs from
  https://attack.mitre.org. A blank entry means the rule
  detects something MacCrab-specific (e.g., AI Guard
  cluster) that doesn't have a perfect ATT&CK mapping.

## Related docs

- [`THREAT_MODEL.md`](THREAT_MODEL.md) — what classes of attacker MacCrab does and doesn't defend against
- [`RESPONSE_SAFETY.md`](RESPONSE_SAFETY.md) — what response actions can fire when these rules trigger
- [`MODULES.md`](MODULES.md) — stable vs experimental subsystem labels
