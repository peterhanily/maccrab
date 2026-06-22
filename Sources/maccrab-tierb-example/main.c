// maccrab-tierb-example — the reference Tier-B forensic collector. The minimal
// "hello world" a third-party contributor copies: a standalone executable that
// speaks the frozen TierBIPC stdin/stdout contract (see TierBIPC.swift).
//
// Contract:
//   stdin  : the host writes ONE TierBCollectRequest JSON line, then closes it.
//   stdout : the plugin emits zero or more `artifact` JSON lines, then exactly
//            one terminal `result` line (JSONL, one object per line).
//   fd 3   : (sandboxed third-party lane only) the file broker — to READ a
//            manifest-declared file, send a 2-byte-big-endian-length + path
//            frame and receive the fd via SCM_RIGHTS. This example does no file
//            reads, so it never touches fd 3 — the simplest possible collector.
//
// Under the deny-default sandbox this plugin needs nothing but stdout, so it is
// also the corpus ALLOW fixture (F1: a benign plugin runs and emits its result).

#include <stdio.h>
#include <unistd.h>

int main(void) {
    // We don't need the request body; the host tolerates a plugin that never
    // reads stdin (F_SETNOSIGPIPE on its side). A real collector would parse the
    // request for scratchDir + the collection window.

    // One metadata artifact + the terminal result. Host stamps identity + re-hashes.
    fputs("{\"kind\":\"artifact\",\"artifact\":{"
          "\"contentType\":\"example.heartbeat\",\"privacyClass\":\"metadata\","
          "\"summary\":\"reference collector ran\",\"data\":{\"ok\":true}}}\n", stdout);
    fputs("{\"kind\":\"result\",\"result\":{\"status\":\"ok\","
          "\"notes\":[\"maccrab-tierb-example: nothing to collect, all good\"]}}\n", stdout);
    fflush(stdout);
    return 0;
}
