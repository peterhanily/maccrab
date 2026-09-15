#!/usr/bin/python3
"""Exercise copied publisher transport with a fake local curl; never network."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BASE = Path(__file__).resolve().parents[1]
FAKE = 'github_pat_FAKE_OFFLINE_ONLY_123456789'
FAKE_CURL = '''#!/usr/bin/python3
import json,os,pathlib,stat,sys
args=sys.argv[1:]
config=pathlib.Path(args[args.index('--config')+1])
expected=os.environ['OFFLINE_EXPECTED_TOKEN']
private=stat.S_IMODE(config.stat().st_mode)==0o600 and stat.S_IMODE(config.parent.stat().st_mode)==0o700
record={'argv':args,'credential_in_argv':any(expected in a for a in args),'config_private':private,'config_has_expected':expected in config.read_text(),'config':str(config)}
with open(os.environ['OFFLINE_RECORD'],'a') as output:output.write(json.dumps(record)+'\\n')
if os.environ.get('OFFLINE_FAIL')=='1':raise SystemExit(22)
print(json.dumps({'commit':{'html_url':'https://github.com/example/fixture/commit/'+'a'*40}} if '-X' in args else {'sha':'b'*40}))
'''


class PublisherArgvControls(unittest.TestCase):
    def run_copy(self, name, *, fail=False, malformed=False, trace=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            curl = root / 'fake-curl.py';curl.write_text(FAKE_CURL);curl.chmod(0o755)
            source = (BASE / 'scripts' / name).read_text().replace('/usr/bin/curl',str(curl))
            script = root / name;script.write_text(source)
            (root/'release.json').write_text('{"version":"0.0.1"}\n')
            (root/'Casks').mkdir();(root/'Casks/maccrab.rb').write_text('cask "fixture" do\n version "0.0.1"\nend\n')
            record=root/'calls.jsonl'
            env={'PATH':'/usr/bin:/bin','HOME':directory,'SITE_REPO_TOKEN':FAKE + ('\nheader = \"X-Test: fixture\"' if malformed else ''),'TAP_REPO_TOKEN':FAKE + ('\nheader = \"X-Test: fixture\"' if malformed else ''),
                 'OFFLINE_EXPECTED_TOKEN':FAKE,'OFFLINE_RECORD':str(record),'OFFLINE_FAIL':'1' if fail else '0'}
            result=subprocess.run(['/bin/bash', *(['-x'] if trace else []), str(script)],cwd=root,env=env,text=True,capture_output=True,timeout=15)
            self.assertNotIn(FAKE,result.stdout+result.stderr)
            self.assertEqual(result.returncode == 0,not (fail or malformed))
            if malformed:
                self.assertFalse(record.exists())
                return
            calls=[json.loads(line) for line in record.read_text().splitlines()]
            self.assertGreaterEqual(len(calls),1)
            for row in calls:
                self.assertFalse(row['credential_in_argv'])
                self.assertTrue(row['config_private'] and row['config_has_expected'])
                self.assertEqual(row['argv'][0],'-q')
                self.assertIn('--noproxy',row['argv'])
                self.assertFalse(Path(row['config']).exists())

    def test_metadata_and_tap_credentials_stay_out_of_argv(self):
        for name in ('publish-release-json.sh','publish-cask.sh'):
            with self.subTest(name=name):self.run_copy(name)

    def test_shell_tracing_is_disabled_before_credential_expansion(self):
        for name in ('publish-release-json.sh','publish-cask.sh'):
            with self.subTest(name=name):self.run_copy(name,trace=True)
        for name in ('release.sh','build-release.sh','notarize.sh','publish-appcast-entry.sh'):
            text=(BASE/'scripts'/name).read_text()
            first_statement=next(line.strip() for line in text.splitlines() if line.strip() and not line.startswith('#'))
            self.assertEqual(first_statement,'set +x')

    def test_linebreak_credentials_are_rejected_before_curl(self):
        for name in ('publish-release-json.sh','publish-cask.sh'):
            with self.subTest(name=name):self.run_copy(name,malformed=True)

    def test_http_failure_is_nonzero_and_cleans_auth_config(self):
        for name in ('publish-release-json.sh','publish-cask.sh'):
            with self.subTest(name=name):self.run_copy(name,fail=True)

    def test_appcast_launcher_transfers_only_expected_environment(self):
        source=(BASE/'scripts/release.sh').read_text()
        start=source.index('        if SITE_REPO_TOKEN="$MACCRAB_PUBLISH_SITE_REPO_TOKEN" /usr/bin/python3 -I -B -c ')
        literal=source[start:].split("-c '\n",1)[1].split("\n' \"$BUILD_WORKSPACE",1)[0]
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'fake-publisher.sh'
            target.write_text('#!/bin/bash\n[[ "$SITE_REPO_TOKEN" == "'+FAKE+'" && "$1" == --fixture ]] || exit 8\ncompgen -e\n')
            target.chmod(0o755)
            args=['/usr/bin/python3','-I','-B','-c',literal,str(target),'--fixture']
            self.assertFalse(any(FAKE in arg for arg in args))
            result=subprocess.run(args,env={'HOME':directory,'SITE_REPO_TOKEN':FAKE,'UNRELATED_SECRET':'also-fake'},text=True,capture_output=True,timeout=10,check=True)
            self.assertNotIn(FAKE,result.stdout+result.stderr)
            keys=set(result.stdout.splitlines())
            self.assertNotIn('UNRELATED_SECRET',keys)
            self.assertTrue({'PATH','HOME','TMPDIR','LC_ALL','LANG','SITE_REPO_TOKEN'} <= keys)
            self.assertFalse(keys - {'PATH','HOME','TMPDIR','LC_ALL','LANG','SITE_REPO_TOKEN','PWD','SHLVL','_'})



class NotaryPrivacyControls(unittest.TestCase):
    def script(self):
        return (BASE/'scripts/notarize.sh').read_text()

    def test_password_only_route_fails_before_external_calls_or_sidecar_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);called=root/'called';fake=root/'fake';fake.mkdir()
            catcher=fake/'catch'
            catcher.write_text('#!/bin/bash\nprintf called >> "$OFFLINE_CALLED"\nexit 7\n');catcher.chmod(0o755)
            for name in ('dirname','basename','security','codesign','xcrun','spctl','grep','head','awk','tr','du','cut'):
                (fake/name).symlink_to(catcher.name)
            source=self.script()
            for command in ('/bin/rm','/bin/chmod','/bin/mv','/usr/bin/printf','/usr/bin/tr'):
                source=source.replace(command,str(catcher))
            script=root/'notarize.sh';script.write_text(source)
            dmg=root/'fixture.dmg';dmg.write_bytes(b'fixture')
            sidecar=root/'fixture.dmg.notary-submission-id';sidecar.write_text('retained')
            env={'PATH':str(fake),'HOME':directory,'OFFLINE_CALLED':str(called),
                 'APPLE_ID':'fixture@example.invalid','APPLE_TEAM_ID':'ABCDEFGHIJ','NOTARIZE_PASSWORD':'fake-password'}
            result=subprocess.run(['/bin/bash',str(script),str(dmg)],env=env,text=True,capture_output=True,timeout=10)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('Password-based notarization is disabled',result.stderr+result.stdout)
            self.assertNotIn('fake-password',result.stderr+result.stdout)
            self.assertFalse(called.exists())
            self.assertEqual(sidecar.read_text(),'retained')
            self.assertNotIn('--password',self.script())

    def test_profile_submission_retains_no_legacy_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);fake=root/'fake';fake.mkdir();record=root/'calls'
            tool='''#!/usr/bin/python3
import json,os,sys
name=os.path.basename(sys.argv[0]);args=sys.argv[1:]
with open(os.environ['OFFLINE_RECORD'],'a') as out:out.write(json.dumps({'name':name,'args':args,'legacy_present':any(k in os.environ for k in ('APPLE_ID','APPLE_TEAM_ID','NOTARIZE_PASSWORD'))})+'\\n')
if name=='security':print('Developer ID Application: Fixture (ABCDEFGHIJ)')
if name=='xcrun' and args[:2]==['notarytool','submit']:print('id: 12345678-1234-4234-8234-123456789012\\nstatus: Accepted')
'''
            for name in ('security','codesign','xcrun','spctl'):
                path=fake/name;path.write_text(tool);path.chmod(0o755)
            dmg=root/'fixture.dmg';dmg.write_bytes(b'fixture')
            script=root/'notarize.sh';script.write_text(self.script())
            env={'PATH':str(fake)+':/usr/bin:/bin','HOME':directory,'OFFLINE_RECORD':str(record),
                 'DEVELOPER_ID':'Developer ID Application: Fixture (ABCDEFGHIJ)',
                 'NOTARIZE_KEYCHAIN_PROFILE':'fixture-profile','APPLE_ID':'fixture@example.invalid',
                 'APPLE_TEAM_ID':'ABCDEFGHIJ','NOTARIZE_PASSWORD':'fake-password'}
            result=subprocess.run(['/bin/bash',str(script),str(dmg)],env=env,text=True,capture_output=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            rows=[json.loads(line) for line in record.read_text().splitlines()]
            submit=[row for row in rows if row['name']=='xcrun' and row['args'][:2]==['notarytool','submit']]
            self.assertEqual(len(submit),1)
            self.assertIn('--keychain-profile',submit[0]['args'])
            self.assertTrue(all(not row['legacy_present'] and '--password' not in row['args'] for row in rows))
            self.assertNotIn('fake-password',result.stdout+result.stderr)
            self.assertEqual((root/'fixture.dmg.notary-submission-id').read_text().strip(),
                             'notary_submission_id=12345678-1234-4234-8234-123456789012')


class PrivateRefPrivacyControls(unittest.TestCase):
    def test_private_recovery_refs_are_refused_before_ci(self):
        for local_ref, remote_ref in (("refs/private/fixture", "refs/heads/main"),
                                      ("refs/heads/main", "refs/private/fixture")):
            with self.subTest(local_ref=local_ref), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / '.githooks').mkdir()
                (root / 'scripts').mkdir()
                hook = root / '.githooks/pre-push'
                hook.write_text((BASE / '.githooks/pre-push').read_text())
                ci = root / 'scripts/ci-local.sh'
                ci.write_text('#!/bin/bash\nprintf called > ci-called\n')
                ci.chmod(0o755)
                refs = local_ref + ' ' + 'a' * 40 + ' ' + remote_ref + ' ' + '0' * 40 + '\n'
                result = subprocess.run(['/bin/bash', str(hook)], input=refs,
                                        text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertIn('private recovery refs must never be published', result.stderr)
                self.assertFalse((root / 'ci-called').exists())


class AttestationPrivacyControls(unittest.TestCase):
    def test_public_attestation_keeps_content_hash_without_local_metadata(self):
        source=(BASE/'scripts/build-release.sh').read_text()
        public=source.split('cat > "$ATTESTATION_PATH" <<ATTESTATION_EOF\n',1)[1].split('\nATTESTATION_EOF',1)[0]
        self.assertIn('provisioning_profile_sha256=$PROFILE_SHA_BEFORE',public)
        self.assertNotIn('provisioning_profile_metadata',public)
        self.assertNotIn('PROFILE_STAT_',public)
        for label in ('uid=','gid=','mtime='):
            self.assertNotIn(label,public)

    def test_profile_stable_copy_still_refuses_concurrent_source_change(self):
        source=(BASE/'scripts/build-release.sh').read_text()
        snippet=source.split('        PROFILE_STAT_BEFORE=',1)[1].split('        # Public, content-addressed evidence',1)[0]
        snippet='        PROFILE_STAT_BEFORE='+snippet
        for mutate in (False,True):
            with self.subTest(mutate=mutate),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);profile=root/'profile';profile.write_bytes(b'fixture-profile')
                app=root/'app';(app/'Contents').mkdir(parents=True)
                sysext=root/'sysext';(sysext/'Contents').mkdir(parents=True)
                fake=root/'fake';fake.mkdir()
                cp=fake/'cp';cp.write_text('#!/bin/bash\n/bin/cp "$@"\nif [[ "$OFFLINE_MUTATE" == 1 && "$2" == "$SYSEXT_BUNDLE/Contents/embedded.provisionprofile" ]]; then printf changed >> "$PROVISION_PROFILE"; fi\n');cp.chmod(0o755)
                env={'PATH':str(fake)+':/usr/bin:/bin','PROVISION_PROFILE':str(profile),'APP':str(app),
                     'SYSEXT_BUNDLE':str(sysext),'SHASUM_BIN':'/usr/bin/shasum','OFFLINE_MUTATE':'1' if mutate else '0'}
                result=subprocess.run(['/bin/bash','-eu','-c',snippet],env=env,text=True,capture_output=True,timeout=10)
                self.assertEqual(result.returncode==0,not mutate)
                if mutate:self.assertIn('stable-copy attestation',result.stdout+result.stderr)
                else:self.assertEqual((app/'Contents/embedded.provisionprofile').read_bytes(),profile.read_bytes())


if __name__=='__main__':unittest.main()
