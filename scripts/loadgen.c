#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void die(const char *msg) {
    fprintf(stderr, "loadgen: %s: %s\n", msg, strerror(errno));
    exit(1);
}

static void usage(void) {
    fprintf(stderr,
            "usage:\n"
            "  loadgen udp-sink <ip> <port>\n"
            "  loadgen udp-source <ip> <port> <seconds> <bytes>\n"
            "  loadgen udp-echo <ip> <port>\n"
            "  loadgen udp-rtt <ip> <port> <count>\n"
            "  loadgen tcp-sink <ip> <port> <bytes>\n"
            "  loadgen tcp-source <ip> <port> <bytes>\n");
    exit(2);
}

static unsigned long long now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) die("clock_gettime");
    return (unsigned long long)ts.tv_sec * 1000000000ULL +
           (unsigned long long)ts.tv_nsec;
}

static double seconds_since(unsigned long long start, unsigned long long end) {
    if (end <= start) return 0.000001;
    return (double)(end - start) / 1e9;
}

static unsigned long long parse_u64(const char *s) {
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        fprintf(stderr, "loadgen: invalid integer: %s\n", s);
        exit(2);
    }
    return v;
}

static double parse_double(const char *s) {
    char *end = NULL;
    errno = 0;
    double v = strtod(s, &end);
    if (errno != 0 || end == s || *end != '\0' || v <= 0.0) {
        fprintf(stderr, "loadgen: invalid duration: %s\n", s);
        exit(2);
    }
    return v;
}

static struct sockaddr_in ipv4_addr(const char *ip, unsigned short port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "loadgen: invalid IPv4 address: %s\n", ip);
        exit(2);
    }
    return addr;
}

static int udp_socket(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) die("socket(udp)");
    int buf = 8 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NO_CHECK, &one, sizeof(one));
    return fd;
}

static int tcp_socket(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket(tcp)");
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    int buf = 8 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    return fd;
}

static void print_udp_result(const char *role, unsigned long long packets,
                             unsigned long long bytes, double seconds) {
    double pps = seconds > 0.0 ? (double)packets / seconds : 0.0;
    double gbps = seconds > 0.0 ? (double)bytes * 8.0 / seconds / 1e9 : 0.0;
    printf("RESULT proto=udp role=%s packets=%llu bytes=%llu seconds=%.6f "
           "pps=%.0f gbps=%.6f\n",
           role, packets, bytes, seconds, pps, gbps);
}

static void print_tcp_result(const char *role, unsigned long long bytes,
                             double seconds) {
    double gbps = seconds > 0.0 ? (double)bytes * 8.0 / seconds / 1e9 : 0.0;
    printf("RESULT proto=tcp role=%s bytes=%llu seconds=%.6f gbps=%.6f\n",
           role, bytes, seconds, gbps);
}

static int cmd_udp_sink(const char *ip, const char *port_s) {
    unsigned short port = (unsigned short)parse_u64(port_s);
    struct sockaddr_in addr = ipv4_addr(ip, port);
    int fd = udp_socket();
    if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0)
        die("bind(udp)");
    printf("READY\n");
    fflush(stdout);

    enum { batch = 64 };
    unsigned char *buffers = malloc(batch * 2048);
    struct iovec iovs[batch];
    struct mmsghdr msgs[batch];
    if (!buffers) die("malloc");
    for (int i = 0; i < batch; i++) {
        iovs[i].iov_base = buffers + (size_t)i * 2048;
        iovs[i].iov_len = 2048;
        memset(&msgs[i], 0, sizeof(msgs[i]));
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    unsigned long long packets = 0;
    unsigned long long bytes = 0;
    unsigned long long start = 0;
    unsigned long long end = 0;
    int done = 0;

    while (!done) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int rc = poll(&pfd, 1, 5000);
        if (rc < 0) die("poll(udp)");
        if (rc == 0) break;
        for (;;) {
            int n = recvmmsg(fd, msgs, batch, MSG_DONTWAIT, NULL);
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                die("recvmmsg(udp)");
            }
            for (int i = 0; i < n; i++) {
                size_t len = msgs[i].msg_len;
                if (len >= 8 &&
                    memcmp(iovs[i].iov_base, "VNETQUIT", 8) == 0) {
                    done = 1;
                    break;
                }
                unsigned long long t = now_ns();
                if (packets == 0) start = t;
                end = t;
                packets++;
                bytes += len;
            }
            if (done) break;
        }
    }
    close(fd);
    if (packets == 0) {
        fprintf(stderr, "loadgen: udp-sink received no packets\n");
        return 1;
    }
    print_udp_result("server", packets, bytes, seconds_since(start, end));
    return 0;
}

static int cmd_udp_source(const char *ip, const char *port_s,
                          const char *seconds_s, const char *bytes_s) {
    unsigned short port = (unsigned short)parse_u64(port_s);
    double duration = parse_double(seconds_s);
    size_t size = (size_t)parse_u64(bytes_s);
    if (size < 8 || size > 65507) {
        fprintf(stderr, "loadgen: UDP payload must be 8..65507 bytes\n");
        return 2;
    }
    struct sockaddr_in addr = ipv4_addr(ip, port);
    int fd = udp_socket();
    if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0)
        die("connect(udp)");

    unsigned char *buf = malloc(size);
    if (!buf) die("malloc");
    memset(buf, 0, size);
    memcpy(buf, "VNETDATA", 8);

    enum { batch = 64 };
    struct iovec iovs[batch];
    struct mmsghdr msgs[batch];
    for (int i = 0; i < batch; i++) {
        iovs[i].iov_base = buf;
        iovs[i].iov_len = size;
        memset(&msgs[i], 0, sizeof(msgs[i]));
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    unsigned long long packets = 0;
    unsigned long long bytes = 0;
    unsigned long long start = now_ns();
    unsigned long long deadline = start + (unsigned long long)(duration * 1e9);
    unsigned long long next_check = start + 100000000ULL;
    for (;;) {
        unsigned long long t = now_ns();
        if (t >= next_check) {
            if (t >= deadline) break;
            next_check = t + 100000000ULL;
        }
        int n = sendmmsg(fd, msgs, batch, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = {.fd = fd, .events = POLLOUT};
                poll(&pfd, 1, 10);
                continue;
            }
            die("sendmmsg(udp)");
        }
        packets += (unsigned long long)n;
        bytes += (unsigned long long)n * size;
    }
    unsigned long long end = now_ns();
    for (int i = 0; i < 5; i++) {
        memcpy(buf, "VNETQUIT", 8);
        send(fd, buf, 8, 0);
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10000000};
        nanosleep(&ts, NULL);
    }
    close(fd);
    free(buf);
    print_udp_result("client", packets, bytes, seconds_since(start, end));
    return 0;
}

static int cmd_udp_echo(const char *ip, const char *port_s) {
    unsigned short port = (unsigned short)parse_u64(port_s);
    struct sockaddr_in addr = ipv4_addr(ip, port);
    int fd = udp_socket();
    if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0)
        die("bind(udp)");
    printf("READY\n");
    fflush(stdout);
    unsigned char buf[2048];
    for (;;) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&peer, &peer_len);
        if (n < 0) {
            if (errno == EINTR) continue;
            die("recvfrom(udp)");
        }
        if (sendto(fd, buf, (size_t)n, 0, (struct sockaddr *)&peer, peer_len) < 0)
            die("sendto(udp)");
    }
    return 0;
}

static int cmp_ull(const void *a, const void *b) {
    unsigned long long x = *(const unsigned long long *)a;
    unsigned long long y = *(const unsigned long long *)b;
    return (x > y) - (x < y);
}

static int cmd_udp_rtt(const char *ip, const char *port_s, const char *count_s) {
    unsigned short port = (unsigned short)parse_u64(port_s);
    size_t count = (size_t)parse_u64(count_s);
    if (count == 0) {
        fprintf(stderr, "loadgen: count must be positive\n");
        return 2;
    }
    struct sockaddr_in addr = ipv4_addr(ip, port);
    int fd = udp_socket();
    if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0)
        die("connect(udp)");
    unsigned long long *samples = calloc(count, sizeof(*samples));
    if (!samples) die("calloc");
    unsigned char buf[64];
    size_t lost = 0;
    for (size_t i = 0; i < count; i++) {
        memset(buf, 0, sizeof(buf));
        memcpy(buf, "VNETRTT", 7);
        unsigned long long t0 = now_ns();
        if (send(fd, buf, sizeof(buf), 0) != (ssize_t)sizeof(buf))
            die("send(udp)");
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int rc = poll(&pfd, 1, 2000);
        if (rc == 0) {
            lost++;
            continue;
        }
        if (rc < 0) {
            if (errno == EINTR) {
                i--;
                continue;
            }
            die("poll(udp)");
        }
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) die("recv(udp)");
        samples[i] = now_ns() - t0;
    }
    close(fd);
    size_t got = count - lost;
    if (got == 0) {
        free(samples);
        fprintf(stderr, "loadgen: udp-rtt received no replies\n");
        return 1;
    }
    qsort(samples, got, sizeof(*samples), cmp_ull);
    unsigned long long p50 = samples[(got - 1) * 50 / 100];
    unsigned long long p99 = samples[(got - 1) * 99 / 100];
    unsigned long long max = samples[got - 1];
    printf("RESULT proto=udp role=rtt count=%zu lost=%zu p50_us=%.1f "
           "p99_us=%.1f max_us=%.1f\n",
           count, lost, (double)p50 / 1e3, (double)p99 / 1e3,
           (double)max / 1e3);
    free(samples);
    return lost == 0 ? 0 : 1;
}

static int cmd_tcp_sink(const char *ip, const char *port_s, const char *bytes_s) {
    unsigned short port = (unsigned short)parse_u64(port_s);
    unsigned long long want = parse_u64(bytes_s);
    struct sockaddr_in addr = ipv4_addr(ip, port);
    int fd = tcp_socket();
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0)
        die("bind(tcp)");
    if (listen(fd, 1) != 0) die("listen(tcp)");
    printf("READY\n");
    fflush(stdout);

    int conn = accept(fd, NULL, NULL);
    if (conn < 0) die("accept(tcp)");
    close(fd);
    if (want == 0) want = ~0ULL;
    unsigned long long got = 0;
    unsigned long long start = 0;
    unsigned long long end = 0;
    unsigned char buf[1 << 20];
    for (;;) {
        ssize_t n = recv(conn, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            die("recv(tcp)");
        }
        if (n == 0) break;
        unsigned long long t = now_ns();
        if (got == 0) start = t;
        end = t;
        got += (unsigned long long)n;
        if (got >= want) break;
    }
    if (got == 0) {
        close(conn);
        fprintf(stderr, "loadgen: tcp-sink received no data\n");
        return 1;
    }
    if (send(conn, "OK\n", 3, 0) != 3) die("send(tcp)");
    close(conn);
    print_tcp_result("server", got, seconds_since(start, end));
    return 0;
}

static int cmd_tcp_source(const char *ip, const char *port_s,
                          const char *bytes_s) {
    unsigned short port = (unsigned short)parse_u64(port_s);
    unsigned long long want = parse_u64(bytes_s);
    struct sockaddr_in addr = ipv4_addr(ip, port);
    int fd = tcp_socket();
    if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0)
        die("connect(tcp)");
    unsigned char *buf = malloc(1 << 20);
    if (!buf) die("malloc");
    memset(buf, 0, 1 << 20);
    unsigned long long sent = 0;
    unsigned long long start = now_ns();
    while (sent < want) {
        size_t chunk = (size_t)((want - sent) < (1 << 20) ? (want - sent) : (1 << 20));
        size_t off = 0;
        while (off < chunk) {
            ssize_t n = send(fd, buf + off, chunk - off, 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                die("send(tcp)");
            }
            off += (size_t)n;
        }
        sent += chunk;
    }
    unsigned long long end = now_ns();
    if (shutdown(fd, SHUT_WR) != 0) die("shutdown(tcp)");
    char ack[4];
    ssize_t n = recv(fd, ack, sizeof(ack), 0);
    close(fd);
    free(buf);
    if (n <= 0) {
        fprintf(stderr, "loadgen: tcp-source did not receive sink acknowledgement\n");
        return 1;
    }
    print_tcp_result("client", sent, seconds_since(start, end));
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2) usage();
    const char *cmd = argv[1];
    if (strcmp(cmd, "udp-sink") == 0 && argc == 4)
        return cmd_udp_sink(argv[2], argv[3]);
    if (strcmp(cmd, "udp-source") == 0 && argc == 6)
        return cmd_udp_source(argv[2], argv[3], argv[4], argv[5]);
    if (strcmp(cmd, "udp-echo") == 0 && argc == 4)
        return cmd_udp_echo(argv[2], argv[3]);
    if (strcmp(cmd, "udp-rtt") == 0 && argc == 5)
        return cmd_udp_rtt(argv[2], argv[3], argv[4]);
    if (strcmp(cmd, "tcp-sink") == 0 && argc == 5)
        return cmd_tcp_sink(argv[2], argv[3], argv[4]);
    if (strcmp(cmd, "tcp-source") == 0 && argc == 5)
        return cmd_tcp_source(argv[2], argv[3], argv[4]);
    usage();
    return 2;
}
