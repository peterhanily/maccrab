// CTierBBroker — the fiddly SCM_RIGHTS syscall layer for the Tier-B file broker,
// in C so the CMSG_* macros (alignment/space math) are the platform's own and
// not hand-rolled in Swift (a CMSG math bug would be a containment hole).
//
// The broker (host side, TierBFileBroker.swift) opens a manifest-allowlisted file
// SAFELY and passes the resulting fd to the sandboxed plugin over a unix socket;
// the plugin reads from the received fd without ever issuing an open() the
// deny-default sandbox would deny. These three calls are the wire primitive.

#ifndef CMACCRAB_TIERB_BROKER_H
#define CMACCRAB_TIERB_BROKER_H

// Send `fd` over unix-domain socket `sock`, carrying a 1-byte `status` payload
// (SCM_RIGHTS requires at least one byte of regular data). Returns 0 on success,
// -1 on error (errno set). The caller still owns `fd` and should close it.
int maccrab_tierb_send_fd(int sock, int fd, unsigned char status);

// Send a status byte with NO descriptor (e.g. a denial). Returns 0 / -1.
int maccrab_tierb_send_status(int sock, unsigned char status);

// Receive one message. Reads the 1-byte status; if a descriptor was attached,
// returns it via *out_fd (caller owns + must close), else *out_fd = -1. Returns
// the status byte (0..255) on success, or -1 on EOF/error. Any extra descriptors
// beyond the first (never sent by us) are closed to avoid a leak.
int maccrab_tierb_recv_fd(int sock, int *out_fd);

#endif
