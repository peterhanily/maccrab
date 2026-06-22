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
                size_t plen = c->cmsg_len - CMSG_LEN(0);
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
            size_t payload_len = c->cmsg_len - CMSG_LEN(0);
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
