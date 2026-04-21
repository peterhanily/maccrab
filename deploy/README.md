# MacCrab enterprise deployment

This directory contains templates for deploying MacCrab via mobile device
management (MDM) — Jamf Pro, Kandji, Mosyle, JumpCloud, Microsoft Intune,
etc. Deploying via MDM eliminates the user-facing System Settings
approval prompts for the System Extension and Full Disk Access that a
fresh manual install otherwise requires.

## What's here

- **MacCrab.mobileconfig.template** — configuration profile template.
  Unsigned. Customize the five `REPLACE-ME-*` markers (UUIDs, org name,
  description) and sign with your enterprise profile-signing certificate
  before deploying.

## Steps

### 1. Generate fresh UUIDs

```bash
for marker in REPLACE-ME-PARENT-UUID REPLACE-ME-SYSEXT-UUID \
              REPLACE-ME-TCC-UUID REPLACE-ME-LOGIN-UUID \
              REPLACE-ME-UUID; do
  uuid=$(uuidgen)
  sed -i '' "s/${marker}/${uuid}/g" MacCrab.mobileconfig.template
done
```

Also edit `PayloadOrganization` and `PayloadDescription` by hand. Leave
the MacCrab team ID (`79S425CW99`) and bundle IDs (`com.maccrab.agent`,
`com.maccrab.app`) as-is — those are the signed product's identifiers.

### 2. Sign the profile

You'll need an Apple Enterprise / Developer ID profile-signing
certificate in your login keychain:

```bash
/usr/bin/security cms -S -N "Your Certificate Common Name Here" \
  -i MacCrab.mobileconfig.template \
  -o MacCrab.mobileconfig
```

Verify the signature:

```bash
/usr/bin/security cms -D -i MacCrab.mobileconfig \
  -o /tmp/profile.plist
```

If that produces a readable plist, the signature is valid.

### 3. Deploy via your MDM

Upload `MacCrab.mobileconfig` as a **configuration profile** in:

- **Jamf Pro:** Computers → Configuration Profiles → Upload → scope to
  target smart group.
- **Kandji:** Library → Custom Profile → Upload.
- **Mosyle:** Management → Profiles → Add → Custom Payload.
- **Microsoft Intune:** Devices → macOS → Configuration profiles →
  Templates → Custom → upload.
- **JumpCloud:** Policies → Mac → upload as custom policy.

### 4. Install MacCrab.app

After the profile is live on managed Macs, push MacCrab.app through
your usual software-distribution channel (Munki, Kandji Self Service,
Jamf Self Service, etc.). First launch will activate the sysext
automatically — **no System Settings prompt** because the profile
pre-authorized it.

## What the profile grants

| Payload | Effect |
| --- | --- |
| `com.apple.system-extension-policy` | Pre-authorizes `com.maccrab.agent` — no user approval prompt |
| `com.apple.TCC.configuration-profile-policy` | Grants Full Disk Access to both `com.maccrab.app` and `com.maccrab.agent` |
| `com.apple.servicemanagement` | Registers MacCrab.app as a login item so protection resumes after reboot |

## Security notes

- **Code requirement strings** pin to Apple's root, the Developer ID leaf
  certificate type, and team ID `79S425CW99`. If you rewrite these, make
  sure the new identity actually matches the signed binaries you're
  distributing — a mismatched requirement means TCC silently won't grant
  access and users will see detection gaps with no clear error.
- **Sign the profile itself.** An unsigned `.mobileconfig` installs but
  a signed one is required for MDM-managed silent install. Apple's docs:
  <https://support.apple.com/guide/deployment/intro-to-configuration-profiles-depc0aadd3fe>.
- **Keep the signed output out of source control.** Only this unsigned
  template is safe to commit.

## Rollback

To remove the profile from a managed Mac, either:

- Unscope it in your MDM (the Mac will remove it on next policy check).
- Manually: System Settings → Privacy & Security → Profiles → MacCrab → −.
- Via CLI: `sudo profiles remove -I com.maccrab.deploy.<payload-identifier>`.

Removing the profile re-enables the normal user-approval flow. The sysext
stays installed — it'll just prompt the user for approval the next time
it reactivates.
