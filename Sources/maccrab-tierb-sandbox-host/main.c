// maccrab-tierb-sandbox-host — the signed self-sandboxing trampoline that runs an
// UNTRUSTED third-party Tier-B plugin under a manifest-derived deny-default
// sandbox profile.
//
// WHY THIS EXISTS (Stream-0 spike, 2026-06-18, macOS 26.3): a `(deny default)`
// profile applied at EXEC time via `sandbox-exec` aborts the target before our
// profile is evaluated (SIGABRT / `execvp() … Operation not permitted`). The
// validated mechanism is to apply the profile to OURSELVES via `sandbox_init`
// AFTER our own startup (dyld/exec already done), THEN `execv` the verified
// plugin — the sandbox is a process attribute and is inherited across exec, so
// the plugin runs contained. This binary IS that trampoline: our code, our
// signature, so the `sandbox_init` deprecation is contained to a binary we own.
//
// THE LOAD-BEARING SAFETY PROPERTY: if `sandbox_init` fails for ANY reason, this
// process exits non-zero and NEVER execs the plugin. An uncontained third-party
// plugin must never run. Same for a missing/oversized/unreadable profile, a
// missing/non-absolute exec target, or a malformed argument — every error path
// is fail-closed (exit before exec).
//
// CONTRACT (the SandboxedTierBRunner host builds exactly this argv):
//   maccrab-tierb-sandbox-host \
//     --profile <sbpl-file>   (REQUIRED; the deny-default .sb the host wrote 0o400)
//     --exec    <plugin-path> (REQUIRED; absolute path to the 0o500 verified temp)
//     [--rlimit-cpu <sec>] [--rlimit-as <bytes>] [--rlimit-nproc <n>]
//     [--rlimit-nofile <n>] [--rlimit-fsize <bytes>]
// stdin/stdout/stderr (fds 0/1/2) and the reserved broker fd 3 are inherited
// across execv unchanged — the host's TierBIPC stdin/stdout contract and the
// (future) fd-3 broker survive the trampoline untouched.
//
// DEVICE-ITERATION NOTE (Streams 0-1, operator-gated): the exact rlimit values
// and the SBPL runtime base that lets a full Swift plugin start while still
// denying the adversarial corpus are PROVEN on a physical macOS host, not here.
// This trampoline is the mechanism; the corpus client-test is the proof.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/stat.h>

// sandbox_init / sandbox_free live in <sandbox.h> (libSystem). Apple marks them
// deprecated; the deprecation is contained because THIS binary is ours.
#include <sandbox.h>

// Exit codes (sysexits-flavoured) so the host can tell apart fail-closed reasons.
#define EX_USAGE_      64   // bad arguments
#define EX_NOINPUT_    66   // profile unreadable
#define EX_SANDBOX_    71   // sandbox_init failed — refused to exec (the key one)
#define EX_EXEC_       72   // execv failed after the sandbox was applied

#define MAX_PROFILE_BYTES (256 * 1024)   // an SBPL profile far larger than ours

static void die(int code, const char *msg) {
    // Single, terse stderr line; the host captures stderr's tail.
    fputs("maccrab-tierb-sandbox-host: ", stderr);
    fputs(msg, stderr);
    fputc('\n', stderr);
    _exit(code);
}

// Read a small file with O_NOFOLLOW (defeats a symlink swap of the profile temp)
// into a freshly-allocated NUL-terminated buffer. Caller frees. Fail-closed.
static char *read_profile(const char *path) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) die(EX_NOINPUT_, "cannot open --profile (O_NOFOLLOW)");

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); die(EX_NOINPUT_, "cannot fstat --profile"); }
    if (!S_ISREG(st.st_mode)) { close(fd); die(EX_NOINPUT_, "--profile is not a regular file"); }
    if (st.st_size <= 0 || st.st_size > MAX_PROFILE_BYTES) {
        close(fd); die(EX_NOINPUT_, "--profile empty or too large");
    }
    // The trampoline is the signed last line of defense; it must not trust the
    // spawner's file. The host writes the profile owned-by-us + 0o400, so anything
    // else is a swap. (A same-uid content rewrite is additionally caught by the
    // deny-default content assertion below — that is the load-bearing check.)
    if (st.st_uid != geteuid()) { close(fd); die(EX_NOINPUT_, "--profile not owned by the trampoline uid"); }
    if ((st.st_mode & 0777) != 0400) { close(fd); die(EX_NOINPUT_, "--profile must be mode 0400"); }

    size_t n = (size_t)st.st_size;
    char *buf = (char *)malloc(n + 1);
    if (!buf) { close(fd); die(EX_NOINPUT_, "oom reading --profile"); }

    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            free(buf); close(fd); die(EX_NOINPUT_, "read error on --profile");
        }
        // A short read (fewer bytes than fstat reported) could silently drop
        // trailing rules from the SBPL → fail-closed rather than sandbox_init a
        // truncated policy.
        if (r == 0) { free(buf); close(fd); die(EX_NOINPUT_, "--profile shorter than stat (truncated)"); }
        got += (size_t)r;
    }
    close(fd);
    buf[got] = '\0';
    // A NUL embedded before EOF would truncate the SBPL passed to sandbox_init,
    // silently dropping later (deny) rules → fail-closed instead.
    if (strlen(buf) != got) { free(buf); die(EX_NOINPUT_, "--profile contains an embedded NUL"); }
    // Content fail-closed: this trampoline ONLY applies MacCrab's own
    // deny-default profiles. A profile missing `(deny default)`, or one that
    // re-opens the baseline with `(allow default)`, is a swap — refuse it rather
    // than sandbox_init a weaker-than-intended policy. This is the check that
    // actually defends against a same-uid content rewrite of the profile temp.
    if (strstr(buf, "(deny default)") == NULL) { free(buf); die(EX_NOINPUT_, "--profile is not deny-default"); }
    if (strstr(buf, "(allow default)") != NULL) { free(buf); die(EX_NOINPUT_, "--profile contains (allow default) — refused"); }
    return buf;
}

// Parse an unsigned long long argument; fail-closed on garbage. Rejects signed
// input (strtoull would wrap "-1" to UINT64_MAX) and any value >= RLIM_INFINITY
// (which would mean "no limit" — never what the host intends for a bound).
static rlim_t parse_rlim(const char *s, const char *what) {
    if (s[0] == '-' || s[0] == '+') die(EX_USAGE_, what);
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || (end && *end != '\0')) die(EX_USAGE_, what);
    if (v >= (unsigned long long)RLIM_INFINITY) die(EX_USAGE_, what);
    return (rlim_t)v;
}

// Set a single soft+hard limit; a setrlimit failure is fatal (fail-closed —
// we will not run the plugin without the resource bound the host asked for).
static void set_one_rlimit(int resource, rlim_t value, const char *what) {
    struct rlimit rl;
    rl.rlim_cur = value;
    rl.rlim_max = value;
    if (setrlimit(resource, &rl) != 0) die(EX_USAGE_, what);
}

int main(int argc, char *argv[]) {
    const char *profile_path = NULL;
    const char *exec_path = NULL;
    // 0 == "not specified" → leave the inherited limit alone.
    rlim_t lim_cpu = 0, lim_as = 0, lim_nproc = 0, lim_nofile = 0, lim_fsize = 0;
    int have_cpu = 0, have_as = 0, have_nproc = 0, have_nofile = 0, have_fsize = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT_ARG(name) do { if (i + 1 >= argc) die(EX_USAGE_, name " needs a value"); } while (0)
        if (strcmp(a, "--profile") == 0)        { NEXT_ARG("--profile"); profile_path = argv[++i]; }
        else if (strcmp(a, "--exec") == 0)      { NEXT_ARG("--exec");    exec_path = argv[++i]; }
        else if (strcmp(a, "--rlimit-cpu") == 0)   { NEXT_ARG("--rlimit-cpu");    lim_cpu    = parse_rlim(argv[++i], "bad --rlimit-cpu");    have_cpu = 1; }
        else if (strcmp(a, "--rlimit-as") == 0)    { NEXT_ARG("--rlimit-as");     lim_as     = parse_rlim(argv[++i], "bad --rlimit-as");     have_as = 1; }
        else if (strcmp(a, "--rlimit-nproc") == 0) { NEXT_ARG("--rlimit-nproc");  lim_nproc  = parse_rlim(argv[++i], "bad --rlimit-nproc");  have_nproc = 1; }
        else if (strcmp(a, "--rlimit-nofile") == 0){ NEXT_ARG("--rlimit-nofile"); lim_nofile = parse_rlim(argv[++i], "bad --rlimit-nofile"); have_nofile = 1; }
        else if (strcmp(a, "--rlimit-fsize") == 0) { NEXT_ARG("--rlimit-fsize");  lim_fsize  = parse_rlim(argv[++i], "bad --rlimit-fsize");  have_fsize = 1; }
        else { die(EX_USAGE_, "unknown argument"); }
        #undef NEXT_ARG
    }

    // Both required — no profile, no exec. Fail-closed.
    if (!profile_path) die(EX_USAGE_, "--profile is required (refusing to run uncontained)");
    if (!exec_path)    die(EX_USAGE_, "--exec is required");
    if (exec_path[0] != '/') die(EX_USAGE_, "--exec must be an absolute path");

    // Read the SBPL BEFORE applying the sandbox (the profile temp is outside the
    // deny-default allow set; after sandbox_init we could not read it).
    char *profile = read_profile(profile_path);

    // Resource bounds, applied before the sandbox and before exec so they are
    // inherited by the plugin image. setrlimit persists across execv.
    if (have_cpu)    set_one_rlimit(RLIMIT_CPU,    lim_cpu,    "setrlimit RLIMIT_CPU failed");
    if (have_as)     set_one_rlimit(RLIMIT_AS,     lim_as,     "setrlimit RLIMIT_AS failed");
    if (have_fsize)  set_one_rlimit(RLIMIT_FSIZE,  lim_fsize,  "setrlimit RLIMIT_FSIZE failed");
    if (have_nofile) set_one_rlimit(RLIMIT_NOFILE, lim_nofile, "setrlimit RLIMIT_NOFILE failed");
    // NPROC last: once it is low, even our own (non-forking) execv is safe, but a
    // failed setrlimit earlier could not spawn a helper to report. Order matters.
    if (have_nproc)  set_one_rlimit(RLIMIT_NPROC,  lim_nproc,  "setrlimit RLIMIT_NPROC failed");

    // THE containment step. Apply the manifest-derived deny-default profile to
    // ourselves. On ANY failure we exit WITHOUT exec — never run uncontained.
    char *sb_err = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    int rc = sandbox_init(profile, 0, &sb_err);
#pragma clang diagnostic pop
    free(profile);
    if (rc != 0) {
        if (sb_err) { fputs("maccrab-tierb-sandbox-host: sandbox_init: ", stderr); fputs(sb_err, stderr); fputc('\n', stderr); }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        if (sb_err) sandbox_free_error(sb_err);
#pragma clang diagnostic pop
        _exit(EX_SANDBOX_);   // fail-closed: contained-or-nothing
    }

    // Sandbox is live and inherited across exec. Run the verified plugin with a
    // clean argv[0] == the plugin path; inherit the (host-scrubbed) environ and
    // all open fds (0/1/2 + the reserved broker fd 3).
    char *child_argv[2] = { (char *)exec_path, NULL };
    execv(exec_path, child_argv);

    // Only reached if execv failed (e.g. the plugin temp vanished or its own
    // process-exec is denied by the profile). The sandbox is already applied, so
    // there is no uncontained-exec risk here — just report and exit.
    die(EX_EXEC_, "execv of --exec failed (under sandbox)");
    return EX_EXEC_;   // unreachable; keeps the compiler happy
}
