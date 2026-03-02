/*
 * Copyright (C) 2019-2025 by Sukchan Lee <acetcom@gmail.com>
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

#include "dhcp-client.h"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
#define close(s) closesocket(s)
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#endif

/* -----------------------------------------------------------------------
 * DHCP packet layout (RFC 2131)
 * ----------------------------------------------------------------------- */
#define SMF_DHCP_MAGIC_COOKIE   0x63825363

/* DHCP message types (option 53) */
#define SMF_DHCP_DISCOVER   1
#define SMF_DHCP_OFFER      2
#define SMF_DHCP_REQUEST    3
#define SMF_DHCP_ACK        5
#define SMF_DHCP_NAK        6
#define SMF_DHCP_RELEASE    7

/* BOOTP op codes */
#define SMF_BOOTP_REQUEST   1
#define SMF_BOOTP_REPLY     2

/* Option tags */
#define SMF_DHCP_OPT_MSGTYPE    53
#define SMF_DHCP_OPT_SERVERID   54
#define SMF_DHCP_OPT_REQIP      50
#define SMF_DHCP_OPT_CLIENTID   61
#define SMF_DHCP_OPT_PARAMREQ   55
#define SMF_DHCP_OPT_END        255

typedef struct {
    uint8_t  op;
    uint8_t  htype;
    uint8_t  hlen;
    uint8_t  hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t  chaddr[16];
    uint8_t  sname[64];
    uint8_t  file[128];
    uint32_t magic;
    uint8_t  options[312];
} smf_dhcp_pkt_t;

/* -----------------------------------------------------------------------
 * Internal helpers
 * ----------------------------------------------------------------------- */

/*
 * Generate a 6-byte dummy MAC from the UE's IMSI:
 *   bytes 0-2  = cfg->mac_prefix  (configurable OUI)
 *   bytes 3-5  = lower 24 bits of (last 9 IMSI decimal digits as uint32)
 *
 * Collision-free for any MSIN value < 16,777,216 (2^24).
 */
static void imsi_to_mac(const char *imsi_bcd,
        const uint8_t prefix[3], uint8_t mac[6])
{
    char suffix[10] = "000000000";
    size_t len = strlen(imsi_bcd);

    if (len >= 9)
        memcpy(suffix, imsi_bcd + len - 9, 9);
    else
        memcpy(suffix + (9 - len), imsi_bcd, len);
    suffix[9] = '\0';

    uint32_t n = (uint32_t)strtoul(suffix, NULL, 10); /* max 999,999,999 */

    mac[0] = prefix[0];
    mac[1] = prefix[1];
    mac[2] = prefix[2];
    mac[3] = (n >> 16) & 0xFF;
    mac[4] = (n >>  8) & 0xFF;
    mac[5] =  n        & 0xFF;
}

/* Append a DHCP option (tag, length, value) to the options buffer.
 * Returns the updated pointer past the appended data. */
static uint8_t *opt_put(uint8_t *p, uint8_t tag,
        const void *val, uint8_t len)
{
    *p++ = tag;
    *p++ = len;
    memcpy(p, val, len);
    return p + len;
}

/* Scan the options field of a received DHCP packet for a given tag.
 * Returns pointer to the value byte(s) on success, NULL if not found. */
static const uint8_t *opt_find(const smf_dhcp_pkt_t *pkt,
        size_t pkt_len, uint8_t tag, uint8_t *out_len)
{
    const uint8_t *p = pkt->options;
    const uint8_t *end;

    /* options field starts right after the 4-byte magic cookie */
    end = (const uint8_t *)pkt +
          offsetof(smf_dhcp_pkt_t, options) + sizeof(pkt->options);
    if (pkt_len < offsetof(smf_dhcp_pkt_t, options))
        return NULL;
    end = (const uint8_t *)pkt + pkt_len;

    while (p < end && *p != SMF_DHCP_OPT_END) {
        uint8_t t = *p++;
        if (p >= end) break;
        uint8_t l = *p++;
        if (p + l > end) break;
        if (t == tag) {
            if (out_len) *out_len = l;
            return p;
        }
        p += l;
    }
    return NULL;
}

/* Build the fixed BOOTP/DHCP header fields common to all message types. */
static void pkt_init(smf_dhcp_pkt_t *pkt, uint32_t xid,
        const uint8_t mac[6])
{
    memset(pkt, 0, sizeof(*pkt));
    pkt->op    = SMF_BOOTP_REQUEST;
    pkt->htype = 1;   /* Ethernet */
    pkt->hlen  = 6;
    pkt->xid   = htonl(xid);
    pkt->flags = htons(0x8000); /* request broadcast reply */
    memcpy(pkt->chaddr, mac, 6);
    pkt->magic = htonl(SMF_DHCP_MAGIC_COOKIE);
}

/* Open a UDP socket connected to the DHCP server and set recv timeout. */
static int open_socket(const char *server_addr, uint16_t server_port,
        int timeout_ms)
{
    int fd;
    struct sockaddr_in srv;
#if defined(_WIN32)
    DWORD tv_ms = (DWORD)timeout_ms;
#else
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
#endif

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        ogs_error("DHCP: socket() failed (%d)", errno);
        return -1;
    }

    memset(&srv, 0, sizeof(srv));
    srv.sin_family      = AF_INET;
    srv.sin_port        = htons(server_port);
    if (inet_pton(AF_INET, server_addr, &srv.sin_addr) != 1) {
        ogs_error("DHCP: invalid server address '%s'", server_addr);
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        ogs_error("DHCP: connect() failed (%d)", errno);
        close(fd);
        return -1;
    }

#if defined(_WIN32)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
               (const char *)&tv_ms, sizeof(tv_ms));
#else
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    return fd;
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

smf_dhcp_config_t *smf_dhcp_find_config_by_dnn(const char *dnn)
{
    smf_dhcp_config_t *cfg = NULL;

    ogs_list_for_each(&smf_self()->dhcp_list, cfg)
        if (ogs_strcasecmp(cfg->dnn, dnn) == 0)
            return cfg;

    return NULL;
}

int smf_dhcp_acquire(smf_sess_t *sess, smf_dhcp_config_t *cfg,
        uint32_t *out_ipv4_be)
{
    smf_ue_t *smf_ue = NULL;
    uint8_t mac[6];
    uint32_t xid;
    smf_dhcp_pkt_t pkt;
    uint8_t *opt;
    ssize_t n;
    int fd = -1;
    int attempt;
    int rv = OGS_ERROR;

    uint32_t offered_ip   = 0;
    uint32_t server_id    = 0;
    uint8_t  msg_type     = 0;
    uint8_t  opt_len      = 0;
    const uint8_t *opt_val = NULL;

    /* IMSI → dummy MAC */
    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    ogs_assert(smf_ue);
    imsi_to_mac(smf_ue->imsi_bcd, cfg->mac_prefix, mac);

    ogs_debug("DHCP acquire [%s] MAC=%02x:%02x:%02x:%02x:%02x:%02x server=%s",
              sess->session.name,
              mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
              cfg->server_addr);

    ogs_random((void *)&xid, sizeof(xid));

    fd = open_socket(cfg->server_addr, cfg->server_port, cfg->timeout_ms);
    if (fd < 0)
        return OGS_ERROR;

    /* ----------------------------------------------------------------
     * Phase 1: DISCOVER → OFFER
     * ---------------------------------------------------------------- */
    for (attempt = 0; attempt < cfg->max_retries; attempt++) {

        /* Build DHCP DISCOVER */
        pkt_init(&pkt, xid, mac);
        opt = pkt.options;

        uint8_t disc = SMF_DHCP_DISCOVER;
        opt = opt_put(opt, SMF_DHCP_OPT_MSGTYPE, &disc, 1);

        /* Client Identifier: type 0 (FQDN/string), value = IMSI BCD string */
        {
            uint8_t client_id[1 + OGS_MAX_IMSI_BCD_LEN + 1];
            client_id[0] = 0; /* type: string */
            size_t imsi_len = strlen(smf_ue->imsi_bcd);
            memcpy(client_id + 1, smf_ue->imsi_bcd, imsi_len);
            opt = opt_put(opt, SMF_DHCP_OPT_CLIENTID,
                          client_id, (uint8_t)(1 + imsi_len));
        }

        /* Parameter Request List: subnet mask (1), router (3), lease (51) */
        {
            uint8_t params[] = { 1, 3, 51 };
            opt = opt_put(opt, SMF_DHCP_OPT_PARAMREQ, params, sizeof(params));
        }

        *opt++ = SMF_DHCP_OPT_END;

        n = send(fd, (const char *)&pkt,
                 offsetof(smf_dhcp_pkt_t, options) + (opt - pkt.options), 0);
        if (n < 0) {
            ogs_error("DHCP: send DISCOVER failed (%d)", errno);
            continue;
        }

        /* Wait for OFFER */
        memset(&pkt, 0, sizeof(pkt));
        n = recv(fd, (char *)&pkt, sizeof(pkt), 0);
        if (n < (ssize_t)offsetof(smf_dhcp_pkt_t, options)) {
            ogs_warn("DHCP: OFFER recv timeout/error (attempt %d)", attempt + 1);
            continue;
        }

        if (ntohl(pkt.magic) != SMF_DHCP_MAGIC_COOKIE) {
            ogs_warn("DHCP: bad magic cookie in response");
            continue;
        }
        if (ntohl(pkt.xid) != xid) {
            ogs_warn("DHCP: xid mismatch in response");
            continue;
        }
        if (pkt.op != SMF_BOOTP_REPLY) {
            ogs_warn("DHCP: expected BOOTREPLY, got op=%d", pkt.op);
            continue;
        }

        opt_val = opt_find(&pkt, (size_t)n, SMF_DHCP_OPT_MSGTYPE, &opt_len);
        if (!opt_val || opt_len < 1 || *opt_val != SMF_DHCP_OFFER) {
            ogs_warn("DHCP: expected OFFER, got type=%d",
                     opt_val ? *opt_val : 0);
            continue;
        }

        offered_ip = pkt.yiaddr; /* already in network byte order */
        if (!offered_ip) {
            ogs_warn("DHCP: OFFER yiaddr is 0");
            continue;
        }

        opt_val = opt_find(&pkt, (size_t)n, SMF_DHCP_OPT_SERVERID, &opt_len);
        if (opt_val && opt_len == 4)
            memcpy(&server_id, opt_val, 4);

        break; /* got a valid OFFER */
    }

    if (!offered_ip) {
        ogs_error("DHCP: no OFFER received after %d attempt(s)", attempt);
        goto done;
    }

    /* ----------------------------------------------------------------
     * Phase 2: REQUEST → ACK
     * ---------------------------------------------------------------- */
    for (attempt = 0; attempt < cfg->max_retries; attempt++) {

        /* Build DHCP REQUEST */
        pkt_init(&pkt, xid, mac);
        opt = pkt.options;

        uint8_t req = SMF_DHCP_REQUEST;
        opt = opt_put(opt, SMF_DHCP_OPT_MSGTYPE, &req, 1);
        opt = opt_put(opt, SMF_DHCP_OPT_REQIP, &offered_ip, 4);
        if (server_id)
            opt = opt_put(opt, SMF_DHCP_OPT_SERVERID, &server_id, 4);

        /* Re-send Client Identifier so the server can match the lease */
        {
            uint8_t client_id[1 + OGS_MAX_IMSI_BCD_LEN + 1];
            client_id[0] = 0;
            size_t imsi_len = strlen(smf_ue->imsi_bcd);
            memcpy(client_id + 1, smf_ue->imsi_bcd, imsi_len);
            opt = opt_put(opt, SMF_DHCP_OPT_CLIENTID,
                          client_id, (uint8_t)(1 + imsi_len));
        }

        *opt++ = SMF_DHCP_OPT_END;

        n = send(fd, (const char *)&pkt,
                 offsetof(smf_dhcp_pkt_t, options) + (opt - pkt.options), 0);
        if (n < 0) {
            ogs_error("DHCP: send REQUEST failed (%d)", errno);
            continue;
        }

        /* Wait for ACK/NAK */
        memset(&pkt, 0, sizeof(pkt));
        n = recv(fd, (char *)&pkt, sizeof(pkt), 0);
        if (n < (ssize_t)offsetof(smf_dhcp_pkt_t, options)) {
            ogs_warn("DHCP: ACK recv timeout/error (attempt %d)", attempt + 1);
            continue;
        }

        if (ntohl(pkt.xid) != xid || pkt.op != SMF_BOOTP_REPLY)
            continue;

        opt_val = opt_find(&pkt, (size_t)n, SMF_DHCP_OPT_MSGTYPE, &opt_len);
        if (!opt_val || opt_len < 1)
            continue;

        msg_type = *opt_val;
        if (msg_type == SMF_DHCP_NAK) {
            ogs_error("DHCP: server sent NAK");
            goto done;
        }
        if (msg_type != SMF_DHCP_ACK) {
            ogs_warn("DHCP: unexpected message type %d", msg_type);
            continue;
        }

        if (!pkt.yiaddr) {
            ogs_warn("DHCP: ACK yiaddr is 0");
            continue;
        }

        *out_ipv4_be = pkt.yiaddr;
        rv = OGS_OK;

        {
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &pkt.yiaddr, addr_str, sizeof(addr_str));
            ogs_info("DHCP: assigned %s to IMSI %s (DNN %s)",
                     addr_str, smf_ue->imsi_bcd, sess->session.name);
        }
        break;
    }

    if (rv != OGS_OK)
        ogs_error("DHCP: no ACK received after %d attempt(s)", attempt);

done:
    close(fd);
    return rv;
}

void smf_dhcp_release(smf_sess_t *sess)
{
    smf_ue_t *smf_ue = NULL;
    smf_dhcp_config_t *cfg = NULL;
    uint8_t mac[6];
    smf_dhcp_pkt_t pkt;
    uint8_t *opt;
    uint32_t xid;
    int fd;

    ogs_assert(sess);
    ogs_assert(sess->ipv4);

    cfg = smf_dhcp_find_config_by_dnn(sess->session.name);
    if (!cfg)
        return; /* not a DHCP session — should not happen */

    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    ogs_assert(smf_ue);
    imsi_to_mac(smf_ue->imsi_bcd, cfg->mac_prefix, mac);

    fd = open_socket(cfg->server_addr, cfg->server_port, cfg->timeout_ms);
    if (fd < 0)
        return;

    ogs_random((void *)&xid, sizeof(xid));

    pkt_init(&pkt, xid, mac);
    /* ciaddr = currently bound address */
    pkt.ciaddr = sess->ipv4->addr[0];

    opt = pkt.options;
    uint8_t rel = SMF_DHCP_RELEASE;
    opt = opt_put(opt, SMF_DHCP_OPT_MSGTYPE, &rel, 1);
    *opt++ = SMF_DHCP_OPT_END;

    send(fd, (const char *)&pkt,
         offsetof(smf_dhcp_pkt_t, options) + (opt - pkt.options), 0);

    {
        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sess->ipv4->addr[0], addr_str, sizeof(addr_str));
        ogs_debug("DHCP: released %s for IMSI %s (DNN %s)",
                  addr_str, smf_ue->imsi_bcd, sess->session.name);
    }

    close(fd);
}
