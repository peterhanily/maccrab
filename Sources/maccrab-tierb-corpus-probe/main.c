// maccrab-tierb-corpus-probe — the adversarial containment corpus fixture. Runs
// UNDER the sandboxed Tier-B lane and probes the boundary, emitting a TierBIPC
// artifact for each forbidden operation that SUCCEEDED. Under correct
// containment the host sees ZERO `leak.*` artifacts and exactly one
// `broker.read.ok` (a DECLARED read served through the broker still works).
//
// This is test/operator tooling (ContainmentCorpusTests + the on-device corpus
// run), NOT a shipped plugin. It is built so the corpus runs against the EXACT
// shipped SandboxedTierBRunner + broker + trampoline, never a prototype.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

#include "cmaccrab_tierb_broker.h"

static void emit(const char *contentType, const char *summary) {
    printf("{\"kind\":\"artifact\",\"artifact\":{\"contentType\":\"%s\","
           "\"privacyClass\":\"metadata\",\"summary\":\"%s\",\"data\":{}}}\n",
           contentType, summary ? summary : "");
}

// Extract the scratchDir value from the request JSON on stdin (crude string
// scan; sufficient for a fixture).
static int read_scratch(char *out, size_t cap) {
    static char buf[8192];
    ssize_t total = 0, r;
    while (total < (ssize_t)sizeof(buf) - 1 && (r = read(0, buf + total, sizeof(buf) - 1 - total)) > 0)
        total += r;
    buf[total > 0 ? total : 0] = '\0';
    const char *key = "\"scratchDir\":\"";
    char *p = strstr(buf, key);
    if (!p) return -1;
    p += strlen(key);
    char *end = strchr(p, '"');
    if (!end) return -1;
    size_t n = (size_t)(end - p);
    if (n >= cap) return -1;
    memcpy(out, p, n);
    out[n] = '\0';
    return 0;
}

int main(void) {
    char scratch[1024] = {0};
    int have_scratch = (read_scratch(scratch, sizeof(scratch)) == 0);

    // ---- ALLOW probe: a DECLARED read served through the broker (fd 3). ----
    // The harness pre-creates <scratch>/allowed.txt; scratch is in the broker
    // policy, so this read SHOULD succeed via a passed fd (we never open() it).
    if (have_scratch) {
        char path[1100];
        snprintf(path, sizeof(path), "%s/allowed.txt", scratch);
        size_t len = strlen(path);
        unsigned char hdr[2] = { (unsigned char)((len >> 8) & 0xFF), (unsigned char)(len & 0xFF) };
        if (write(3, hdr, 2) == 2 && write(3, path, len) == (ssize_t)len) {
            int fd = -1;
            if (maccrab_tierb_recv_fd(3, &fd) == 0 && fd >= 0) {
                char c[64]; ssize_t n = read(fd, c, sizeof(c) - 1);
                if (n > 0) { c[n] = '\0'; emit("broker.read.ok", c); }
                close(fd);
            }
        }
    }

    // ---- DENY battery: every one of these MUST fail under containment. ----
    // (Targets are host-created throwaway files — never a real user store.)

    // F4: open a file outside any declared root (filesystem escape).
    {
        int f = open("/tmp/maccrab-corpus-secret", O_RDONLY);
        if (f >= 0) { emit("leak.file_escape", "opened an undeclared file directly"); close(f); }
    }

    // F9: undeclared network egress.
    {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s >= 0) {
            fcntl(s, F_SETFL, O_NONBLOCK);
            struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET; sa.sin_port = htons(443);
            inet_pton(AF_INET, "1.1.1.1", &sa.sin_addr);
            int rc = connect(s, (struct sockaddr *)&sa, sizeof(sa));
            if (rc == 0 || errno == EINPROGRESS) emit("leak.network", "outbound connect not denied");
            close(s);
        }
    }

    // F11: fork (default fork-deny).
    {
        pid_t pid = fork();
        if (pid == 0) { _exit(0); }
        if (pid > 0) { emit("leak.fork", "fork succeeded"); int st; waitpid(pid, &st, 0); }
    }

    // F-META: stat() a metadata-denied crown-jewel — the existence/size/mtime side
    // channel the deny-default profile must close even though content is brokered.
    // /Library/Keychains exists on every Mac and the profile denies
    // file-read-metadata on it (audit #4).
    {
        struct stat st;
        if (stat("/Library/Keychains", &st) == 0)
            emit("leak.metadata", "stat() of a metadata-denied crown-jewel succeeded");
    }

    // F-MACH: look up a com.apple Mach service that is NOT in the runtime base or
    // the manifest allowlist (sandbox-escape surface). The pasteboard is
    // exfil-relevant and must be unreachable from a contained forensic plugin —
    // under the former global (allow mach-lookup) it resolved; now it must not.
    {
        mach_port_t port = MACH_PORT_NULL;
        kern_return_t kr = bootstrap_look_up(bootstrap_port, "com.apple.pasteboard.1", &port);
        if (kr == KERN_SUCCESS && port != MACH_PORT_NULL)
            emit("leak.mach", "reached an undeclared com.apple Mach service");
    }

    printf("{\"kind\":\"result\",\"result\":{\"status\":\"ok\",\"notes\":[\"corpus probe complete\"]}}\n");
    fflush(stdout);
    return 0;
}
