#define _GNU_SOURCE
#include <errno.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static int set_value(int fd, const char *name, unsigned int cmd, int value) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    struct ethtool_value ev = {.cmd = cmd, .data = (unsigned int)value};
    ifr.ifr_data = (char *)&ev;
    if (ioctl(fd, SIOCETHTOOL, &ifr) != 0) {
        fprintf(stderr, "netdev_offload: %s: %s\n", name, strerror(errno));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: netdev_offload <ifname> <on|off>\n");
        return 2;
    }
    int value;
    if (strcmp(argv[2], "on") == 0) {
        value = 1;
    } else if (strcmp(argv[2], "off") == 0) {
        value = 0;
    } else {
        fprintf(stderr, "netdev_offload: expected on or off\n");
        return 2;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("netdev_offload: socket");
        return 1;
    }
    int rc = 0;
    rc |= set_value(fd, argv[1], ETHTOOL_STXCSUM, value);
    rc |= set_value(fd, argv[1], ETHTOOL_SGSO, value);
    rc |= set_value(fd, argv[1], ETHTOOL_STSO, value);
    rc |= set_value(fd, argv[1], ETHTOOL_SGRO, value);
    close(fd);
    return rc == 0 ? 0 : 1;
}
