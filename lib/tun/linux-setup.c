/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "ogs-tun.h"

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __ogs_sock_domain

#include <net/if.h>
#include <net/route.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/if_tun.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 32
#endif

#ifndef OGS_NETNS_RUN_DIR
#define OGS_NETNS_RUN_DIR "/var/run/netns"
#endif

int ogs_netns_enter(const char *netns, ogs_socket_t *old_netns_fd)
{
    char path[OGS_MAX_FILEPATH_LEN];
    int fd;

    ogs_assert(netns);
    ogs_assert(old_netns_fd);

    *old_netns_fd = open("/proc/self/ns/net", O_RDONLY);
    if (*old_netns_fd < 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "open() failed : /proc/self/ns/net");
        *old_netns_fd = INVALID_SOCKET;
        return OGS_ERROR;
    }

    ogs_snprintf(path, sizeof(path), "%s/%s", OGS_NETNS_RUN_DIR, netns);

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "open() failed : netns[%s]", path);
        close(*old_netns_fd);
        *old_netns_fd = INVALID_SOCKET;
        return OGS_ERROR;
    }

    if (setns(fd, CLONE_NEWNET) < 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "setns() failed : netns[%s]", path);
        close(fd);
        close(*old_netns_fd);
        *old_netns_fd = INVALID_SOCKET;
        return OGS_ERROR;
    }

    close(fd);
    return OGS_OK;
}

int ogs_netns_restore(ogs_socket_t old_netns_fd)
{
    if (old_netns_fd == INVALID_SOCKET)
        return OGS_OK;

    if (setns(old_netns_fd, CLONE_NEWNET) < 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "setns() failed : could not restore original netns");
        close(old_netns_fd);
        return OGS_ERROR;
    }

    close(old_netns_fd);
    return OGS_OK;
}

ogs_socket_t ogs_tun_open(char *ifname, int len, int is_tap, const char *netns)
{
    ogs_socket_t fd = INVALID_SOCKET;
    ogs_socket_t old_netns_fd = INVALID_SOCKET;

    const char *dev = "/dev/net/tun";
    int rc;
    struct ifreq ifr;
    int flags = IFF_NO_PI;

    ogs_assert(ifname);

    if (netns) {
        if (ogs_netns_enter(netns, &old_netns_fd) != OGS_OK) {
            ogs_error("ogs_netns_enter() failed : netns[%s]", netns);
            return INVALID_SOCKET;
        }
    }

    fd = open(dev, O_RDWR);
    if (fd < 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "open() failed : dev[%s]", dev);
        ogs_netns_restore(old_netns_fd);
        return INVALID_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = (is_tap ? (flags | IFF_TAP) : (flags | IFF_TUN));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    rc = ioctl(fd, TUNSETIFF, (void *)&ifr);
    if (rc < 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "ioctl() failed : dev[%s] flags[0x%x]", dev, flags);
        goto cleanup;
    }

    ogs_netns_restore(old_netns_fd);

    return fd;

cleanup:
    close(fd);
    ogs_netns_restore(old_netns_fd);
    return INVALID_SOCKET;
}

int ogs_tun_set_ip(char *ifname, ogs_ipsubnet_t *gw, ogs_ipsubnet_t *sub)
{
    return OGS_OK;
}
