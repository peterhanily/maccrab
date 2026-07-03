#include "cmaccrab_tierb_broker.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>

int maccrab_tierb_send_fd(int sock, int fd, unsigned char status) {
    char payload = (char)status;
    struct iovec iov;
    iov.iov_base = &payload;
    iov.iov_len = 1;

    union {
        struct cmsghdr align;          // force correct alignment of buf
        char buf[CMSG_SPACE(sizeof(int))];
    } control;
    memset(&control, 0, sizeof(control));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.buf;
    msg.msg_controllen = sizeof(control.buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    ssize_t n;
    do { n = sendmsg(sock, &msg, 0); } while (n < 0 && errno == EINTR);
    return n < 0 ? -1 : 0;
}

int maccrab_tierb_send_status(int sock, unsigned char status) {
    char b = (char)status;
    ssize_t n;
    do { n = send(sock, &b, 1, 0); } while (n < 0 && errno == EINTR);
    return n < 0 ? -1 : 0;
}

// SCM_RIGHTS payload length, hardened against a malformed/hostile peer:
//  (1) refuse to underflow when cmsg_len < CMSG_LEN(0) — a truncated cmsg would
//      otherwise wrap size_t to a huge value → a wild buffer over-read + closing
//      garbage descriptors; and
//  (2) clamp to the control bytes actually received (msg_controllen), since a
//      MSG_CTRUNC reply can leave cmsg_len claiming more fds than the buffer holds.
static size_t scm_payload_len(struct msghdr *msg, struct cmsghdr *c) {
    if (c->cmsg_len < CMSG_LEN(0)) return 0;
    size_t plen = (size_t)c->cmsg_len - CMSG_LEN(0);
    char *data = (char *)CMSG_DATA(c);
    char *ctl_end = (char *)msg->msg_control + msg->msg_controllen;
    size_t avail = (data < ctl_end) ? (size_t)(ctl_end - data) : 0;
    return plen < avail ? plen : avail;
}

int maccrab_tierb_recv_fd(int sock, int *out_fd) {
    if (out_fd) *out_fd = -1;

    char payload = 0;
    struct iovec iov;
    iov.iov_base = &payload;
    iov.iov_len = 1;

    union {
        struct cmsghdr align;
        char buf[CMSG_SPACE(sizeof(int))];
    } control;
    memset(&control, 0, sizeof(control));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.buf;
    msg.msg_controllen = sizeof(control.buf);

    ssize_t n;
    do { n = recvmsg(sock, &msg, 0); } while (n < 0 && errno == EINTR);
    if (n <= 0) return -1;

    int found = -1;
    // Control data truncated → a hostile peer attached more than one descriptor.
    // Extract+close whatever we can and fail; never report a possibly-leaked fd.
    if (msg.msg_flags & MSG_CTRUNC) {
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c != NULL; c = CMSG_NXTHDR(&msg, c)) {
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
                size_t plen = scm_payload_len(&msg, c);   // underflow-safe + buffer-clamped
                for (size_t i = 0; i < plen / sizeof(int); i++) {
                    int fd; memcpy(&fd, CMSG_DATA(c) + i * sizeof(int), sizeof(int)); close(fd);
                }
            }
        }
        return -1;
    }

    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c != NULL; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
            // Count the descriptors carried in this cmsg; keep the first, close
            // the rest (we never send more than one, so this only fires on a
            // malformed/hostile peer — fail safe by not leaking).
            size_t payload_len = scm_payload_len(&msg, c);
            size_t count = payload_len / sizeof(int);
            for (size_t i = 0; i < count; i++) {
                int fd;
                memcpy(&fd, CMSG_DATA(c) + i * sizeof(int), sizeof(int));
                if (found < 0) {
                    found = fd;
                } else {
                    close(fd);
                }
            }
        }
    }
    if (out_fd) *out_fd = found;
    return (int)(unsigned char)payload;
}

int maccrab_tierb_broker_open(int sock, const char *path) {
    if (sock < 0 || path == NULL) return -1;
    size_t len = strlen(path);
    if (len == 0 || len > 0xFFFF) return -1;   // 2-byte length frame

    unsigned char hdr[2] = { (unsigned char)((len >> 8) & 0xFF),
                             (unsigned char)(len & 0xFF) };
    // Write the 2-byte length header then the path, tolerating partial writes.
    size_t hoff = 0;
    while (hoff < 2) {
        ssize_t w = write(sock, hdr + hoff, 2 - hoff);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
        hoff += (size_t)w;
    }
    size_t poff = 0;
    while (poff < len) {
        ssize_t w = write(sock, path + poff, len - poff);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
        poff += (size_t)w;
    }

    int fd = -1;
    int status = maccrab_tierb_recv_fd(sock, &fd);   // 0 == ok; else denial/error
    if (status != 0 || fd < 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}
