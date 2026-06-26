#!/usr/bin/env bash
# test-broker-fuzz.sh — adversarial fuzz/stress of the Tier-B SCM_RIGHTS fd broker
# (Sources/CTierBBroker/broker.c). A hostile peer sends thousands of malformed /
# multi-fd control messages to maccrab_tierb_recv_fd over a unix socketpair; the
# receiver is built with AddressSanitizer + UndefinedBehaviorSanitizer so any
# buffer over-read or size_t underflow in the CMSG parser aborts loudly.
#
# This exercises the exact path that produced the v1.20.2 CWE-191 fix: a peer
# attaching MORE descriptors than the 1-fd receive buffer holds → MSG_CTRUNC +
# an over-claimed cmsg_len. PASS = the broker survives every message with no
# sanitizer fault and no stray fd closed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d /tmp/maccrab-brokerfuzz.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
ITERS="${1:-20000}"

cat > "$WORK/harness.c" <<'C'
#include "cmaccrab_tierb_broker.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

// Hostile sender: attach `nfds` real descriptors with a crafted SCM_RIGHTS
// header. nfds>1 forces MSG_CTRUNC on the 1-fd receiver (the v1.20.2 bug path).
static void hostile_send(int sock, int nfds) {
    char payload = (char)(rand() & 0xff);
    struct iovec iov = { &payload, 1 };
    struct msghdr msg; memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    char ctrl[CMSG_SPACE(sizeof(int) * 8)];
    int fds[8];
    if (nfds > 0) {
        memset(ctrl, 0, sizeof(ctrl));
        for (int i = 0; i < nfds; i++) fds[i] = open("/dev/null", O_RDONLY);
        msg.msg_control = ctrl;
        msg.msg_controllen = CMSG_SPACE(sizeof(int) * nfds);
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int) * nfds);
        memcpy(CMSG_DATA(c), fds, sizeof(int) * nfds);
        msg.msg_controllen = c->cmsg_len;
    }
    (void)sendmsg(sock, &msg, 0);
    for (int i = 0; i < nfds; i++) close(fds[i]);
}

int main(int argc, char **argv) {
    long iters = argc > 1 ? atol(argv[1]) : 20000;
    unsigned seed = argc > 2 ? (unsigned)atoi(argv[2]) : 1;
    srand(seed);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return 2; }

    pid_t pid = fork();
    if (pid == 0) {                          // child = hostile sender
        close(sv[0]);
        for (long i = 0; i < iters; i++) hostile_send(sv[1], rand() % 7);  // 0..6 fds
        close(sv[1]);
        _exit(0);
    }
    close(sv[1]);                            // parent = the broker's receiver

    // Sentinels: if the buggy parser close()s a garbage fd value, one of these
    // (a dense block of open fds) is likely to vanish — a second detector
    // beyond the sanitizer's over-read catch.
    int sentinels[64];
    for (int i = 0; i < 64; i++) sentinels[i] = open("/dev/null", O_RDONLY);

    long got = 0, closed_sentinel = 0;
    for (long i = 0; i < iters; i++) {
        int out = -1;
        int rc = maccrab_tierb_recv_fd(sv[0], &out);
        if (rc < 0 && errno == 0 && out < 0) { /* peer closed / truncated → fine */ }
        if (out >= 0) { got++; close(out); }
        if ((i & 0x3ff) == 0) {              // periodic sentinel sweep
            for (int s = 0; s < 64; s++)
                if (fcntl(sentinels[s], F_GETFD) == -1) { closed_sentinel++; sentinels[s] = open("/dev/null", O_RDONLY); }
        }
    }
    close(sv[0]);
    int st; waitpid(pid, &st, 0);
    fprintf(stderr, "broker-fuzz: %ld messages, %ld fds received, %ld stray-closed sentinels\n",
            iters, got, closed_sentinel);
    if (closed_sentinel > 0) { fprintf(stderr, "FAIL: parser closed unrelated descriptor(s)\n"); return 1; }
    fprintf(stderr, "PASS: no sanitizer fault, no stray fd closed\n");
    return 0;
}
C

echo ">>> Building broker + fuzz harness with ASan + UBSan"
clang -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
      -I "$ROOT/Sources/CTierBBroker/include" \
      "$ROOT/Sources/CTierBBroker/broker.c" "$WORK/harness.c" -o "$WORK/brokerfuzz" \
  || { echo "compile failed"; exit 2; }

echo ">>> Fuzzing maccrab_tierb_recv_fd ($ITERS hostile messages, 3 seeds)"
rc=0
for seed in 1 7 1337; do
  ASAN_OPTIONS=abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
    "$WORK/brokerfuzz" "$ITERS" "$seed" || rc=$?
done
exit "$rc"
