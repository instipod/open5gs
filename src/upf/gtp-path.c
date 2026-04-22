/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
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

#include "context.h"

#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#if HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif

#if HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#if HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif

#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#if HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif

#if HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

#include "arp-nd.h"
#include "event.h"
#include "gtp-path.h"
#include "pfcp-path.h"
#include "rule-match.h"

#define UPF_GTP_HANDLED     1

const uint8_t proxy_mac_addr[] = { 0x0e, 0x00, 0x00, 0x00, 0x00, 0x01 };

static ogs_pkbuf_pool_t *packet_pool = NULL;

static void upf_gtp_handle_multicast(ogs_pkbuf_t *recvbuf);
static void upf_gtp_handle_tap_ipv6_mcast(
        ogs_pkbuf_t *recvbuf, ogs_pfcp_dev_t *tap_dev);

/*
 * Returns true when pkbuf contains an ICMPv6 Router Solicitation.
 * Mirrors check_if_router_solicit() in src/smf/gtp-path.c.
 */
static bool _check_router_solicit(ogs_pkbuf_t *pkbuf);

/*
 * Build a synthetic solicited Neighbor Advertisement for the gateway link-local
 * address (fe80::1) and deliver it to the UE via its downlink GTP-U tunnel.
 *
 * Called when the UE sends an NS to resolve fe80::1 after receiving the
 * synthetic Router Advertisement.  Rather than forwarding the NS to the real
 * router (which would respond with a unicast NA that gets broadcast to all UEs),
 * we reply directly using the gateway MAC already learned from TAP traffic.
 *
 * ns_src_ip6  – IPv6 source address of the incoming NS (UE's link-local).
 *               This becomes the NA destination.
 * dev         – TAP device; supplies the learned gw6_mac_addr.
 */
static void _send_gateway_neighbor_advertisement(
        upf_sess_t *sess, uint8_t *ns_src_ip6, ogs_pfcp_dev_t *dev)
{
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_user_plane_report_t report;
    ogs_pkbuf_t *pkbuf = NULL;
    uint8_t *p;
    struct ip6_hdr *ip6_h;
    struct nd_neighbor_advert *na_h;
    uint16_t plen;

    /*
     * Gateway link-local: fe80::1  (same address advertised in the
     * synthetic RA; this is both the NA source and the target field).
     * Stored as a byte array to avoid endian-dependent uint32_t tricks.
     */
    static const uint8_t gw_ll_bytes[16] = {
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
#define GW_LL_BYTES gw_ll_bytes

    /* Layout: IPv6(40) + NA header(24) + TLLA option(8) = 72 bytes */
    plen = sizeof(struct nd_neighbor_advert) + 8;   /* NA hdr + TLLA opt */

    pkbuf = ogs_pkbuf_alloc(packet_pool,
                OGS_TUN_MAX_HEADROOM + sizeof(struct ip6_hdr) + plen);
    ogs_assert(pkbuf);
    ogs_pkbuf_reserve(pkbuf, OGS_TUN_MAX_HEADROOM);
    ogs_pkbuf_put(pkbuf, sizeof(struct ip6_hdr) + plen);
    memset(pkbuf->data, 0, pkbuf->len);

    p     = (uint8_t *)pkbuf->data;
    ip6_h = (struct ip6_hdr *)p;
    na_h  = (struct nd_neighbor_advert *)(p + sizeof *ip6_h);

    /* ICMPv6 Neighbor Advertisement (type=136) */
    na_h->nd_na_type           = ND_NEIGHBOR_ADVERT;
    na_h->nd_na_code           = 0;
    na_h->nd_na_cksum          = 0;      /* filled below */
    na_h->nd_na_flags_reserved =
        htobe32(ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE);
    memcpy(na_h->nd_na_target.s6_addr, GW_LL_BYTES, 16);   /* target=fe80::1 */

    /* Target Link-Layer Address option (type=2, len=1 → 8 bytes) */
    uint8_t *opt = p + sizeof *ip6_h + sizeof(struct nd_neighbor_advert);
    opt[0] = ND_OPT_TARGET_LINKADDR;    /* type 2 */
    opt[1] = 1;                         /* len = 1 × 8 = 8 bytes */
    memcpy(opt + 2, dev->gw6_mac_addr, ETHER_ADDR_LEN);

    pkbuf->len = sizeof *ip6_h + plen;

    /* ICMPv6 checksum over IPv6 pseudo-header */
    {
        uint8_t pseudo[40];
        uint16_t plen_be = htobe16(plen);
        memset(pseudo, 0, sizeof pseudo);
        memcpy(pseudo,      GW_LL_BYTES,  16);  /* src = fe80::1 */
        memcpy(pseudo + 16, ns_src_ip6,   16);  /* dst = UE link-local */
        memcpy(pseudo + 32, &plen_be,      2);
        pseudo[39] = IPPROTO_ICMPV6;
        uint32_t sum = 0;
        int i, n;
        uint16_t *w;
        w = (uint16_t *)pseudo; n = sizeof(pseudo) / 2;
        for (i = 0; i < n; i++) sum += w[i];
        w = (uint16_t *)na_h; n = plen / 2;
        for (i = 0; i < n; i++) sum += w[i];
        if (plen & 1) sum += ((uint8_t *)na_h)[plen - 1];
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        na_h->nd_na_cksum = ~(uint16_t)sum;
    }

    /* IPv6 header */
    ip6_h->ip6_flow = htobe32(0x60000000);
    ip6_h->ip6_plen = htobe16(plen);
    ip6_h->ip6_nxt  = IPPROTO_ICMPV6;
    ip6_h->ip6_hlim = 255;
    memcpy(ip6_h->ip6_src.s6_addr, GW_LL_BYTES, 16);   /* fe80::1 */
    memcpy(ip6_h->ip6_dst.s6_addr, ns_src_ip6,   16);   /* UE fe80:: */

    /* Deliver via the session's downlink PDR (CORE → ACCESS) */
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        far = pdr->far;
        if (!far) continue;
        if (pdr->src_if != OGS_PFCP_INTERFACE_CORE) continue;
        if (far->dst_if != OGS_PFCP_INTERFACE_ACCESS) continue;

        ogs_pkbuf_t *sendbuf = ogs_pkbuf_copy(pkbuf);
        if (!sendbuf) break;

        ogs_assert(true == ogs_pfcp_up_handle_pdr(
                    pdr, OGS_GTPU_MSGTYPE_GPDU, 0, NULL, sendbuf, &report));
        ogs_debug("[UPF-TAP] Sent synthetic NA: fe80::1 → %02x:%02x:%02x:%02x:%02x:%02x",
                  dev->gw6_mac_addr[0], dev->gw6_mac_addr[1],
                  dev->gw6_mac_addr[2], dev->gw6_mac_addr[3],
                  dev->gw6_mac_addr[4], dev->gw6_mac_addr[5]);
        break;
    }

    ogs_pkbuf_free(pkbuf);
#undef GW_LL_BYTES
}

static bool _check_router_solicit(ogs_pkbuf_t *pkbuf)
{
    struct ip *ip_h = (struct ip *)pkbuf->data;
    if (ip_h->ip_v != 6) return false;
    if (pkbuf->len < (int)(sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)))
        return false;
    struct ip6_hdr *ip6_h = (struct ip6_hdr *)pkbuf->data;
    if (ip6_h->ip6_nxt != IPPROTO_ICMPV6) return false;
    struct icmp6_hdr *icmp_h =
        (struct icmp6_hdr *)(pkbuf->data + sizeof(struct ip6_hdr));
    return icmp_h->icmp6_type == ND_ROUTER_SOLICIT;
}

/*
 * Build a synthetic Router Advertisement and deliver it to the UE via the
 * session's downlink GTP-U tunnel.
 *
 * ip6_dst is the IPv6 source address of the incoming RS (the UE's link-local).
 * The RA is unicast directly back to that address so other UEs on the same
 * TAP device are not disturbed.
 *
 * Mirrors send_router_advertisement() in src/smf/gtp-path.c.
 */
static void _send_router_advertisement(upf_sess_t *sess, uint8_t *ip6_dst)
{
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_user_plane_report_t report;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_pfcp_ue_ip_t *ue_ip = sess->ipv6;
    uint8_t *p;
    struct ip6_hdr *ip6_h;
    struct nd_router_advert *advert_h;
    struct nd_opt_prefix_info *prefix;
    uint16_t plen;

    if (!ue_ip || !ue_ip->subnet) return;

    /*
     * RA source address: fe80::1
     * Fixed link-local address representing the UPF/gateway on the GTP link.
     * Mirrors the SMF fallback when no link_local_addr is configured.
     */
    uint32_t src6[4] = {
        htobe32(0xfe800000), htobe32(0x00000000),
        htobe32(0x00000000), htobe32(0x00000001)
    };

    pkbuf = ogs_pkbuf_alloc(packet_pool,
                OGS_TUN_MAX_HEADROOM + sizeof(struct ip6_hdr) + 200);
    ogs_assert(pkbuf);
    ogs_pkbuf_reserve(pkbuf, OGS_TUN_MAX_HEADROOM);
    ogs_pkbuf_put(pkbuf, sizeof(struct ip6_hdr) + 200);
    memset(pkbuf->data, 0, pkbuf->len);

    p        = (uint8_t *)pkbuf->data;
    ip6_h    = (struct ip6_hdr *)p;
    advert_h = (struct nd_router_advert *)(p + sizeof *ip6_h);
    prefix   = (struct nd_opt_prefix_info *)
                    (p + sizeof *ip6_h + sizeof *advert_h);

    /* ICMPv6 Router Advertisement */
    advert_h->nd_ra_type            = ND_ROUTER_ADVERT;
    advert_h->nd_ra_code            = 0;
    advert_h->nd_ra_curhoplimit     = 64;
    advert_h->nd_ra_flags_reserved  = 0;
    advert_h->nd_ra_router_lifetime = htobe16(64800);   /* 18 hours */
    advert_h->nd_ra_reachable       = 0;
    advert_h->nd_ra_retransmit      = 0;

    /* Prefix Information Option (type=3, len=4 × 8 = 32 bytes) */
    prefix->nd_opt_pi_type           = ND_OPT_PREFIX_INFORMATION;
    prefix->nd_opt_pi_len            = 4;
    prefix->nd_opt_pi_prefix_len     = OGS_IPV6_DEFAULT_PREFIX_LEN;   /* 64 */
    prefix->nd_opt_pi_flags_reserved =
        ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO;
    prefix->nd_opt_pi_valid_time     = htobe32(0xffffffff);
    prefix->nd_opt_pi_preferred_time = htobe32(0xffffffff);
    memcpy(prefix->nd_opt_pi_prefix.s6_addr,
           ue_ip->addr, OGS_IPV6_DEFAULT_PREFIX_LEN >> 3);  /* /64 */

    plen = sizeof *advert_h + sizeof *prefix;
    pkbuf->len = sizeof *ip6_h + plen;

    /*
     * ICMPv6 checksum over the IPv6 pseudo-header:
     *   src(16) | dst(16) | upper-layer-len(4) | zeros(3) | next-hdr(1)
     * followed by the ICMPv6 payload.
     */
    {
        uint8_t pseudo[40];
        uint16_t plen_be = htobe16(plen);
        memset(pseudo, 0, sizeof pseudo);
        memcpy(pseudo,      src6,    16);
        memcpy(pseudo + 16, ip6_dst, 16);
        memcpy(pseudo + 32, &plen_be, 2);
        pseudo[39] = IPPROTO_ICMPV6;
        /* Checksum covers pseudo-header + ICMPv6 payload together */
        advert_h->nd_ra_cksum = 0;
        uint32_t sum = 0;
        uint16_t *w;
        int i, n;
        /* pseudo-header */
        w = (uint16_t *)pseudo; n = sizeof(pseudo) / 2;
        for (i = 0; i < n; i++) sum += w[i];
        /* ICMPv6 payload */
        w = (uint16_t *)advert_h; n = plen / 2;
        for (i = 0; i < n; i++) sum += w[i];
        if (plen & 1) sum += ((uint8_t *)advert_h)[plen - 1];
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        advert_h->nd_ra_cksum = ~(uint16_t)sum;
    }

    /* IPv6 header */
    ip6_h->ip6_flow = htobe32(0x60000000);
    ip6_h->ip6_plen = htobe16(plen);
    ip6_h->ip6_nxt  = IPPROTO_ICMPV6;
    ip6_h->ip6_hlim = 255;
    memcpy(ip6_h->ip6_src.s6_addr, src6,    16);
    memcpy(ip6_h->ip6_dst.s6_addr, ip6_dst, 16);

    /*
     * Deliver via the session's downlink PDR (CORE → ACCESS).
     * ogs_pfcp_up_handle_pdr() encapsulates in GTP-U and sends to the eNB.
     */
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        far = pdr->far;
        if (!far) continue;
        if (pdr->src_if != OGS_PFCP_INTERFACE_CORE) continue;
        if (far->dst_if != OGS_PFCP_INTERFACE_ACCESS) continue;

        ogs_pkbuf_t *sendbuf = ogs_pkbuf_copy(pkbuf);
        if (!sendbuf) break;

        ogs_assert(true == ogs_pfcp_up_handle_pdr(
                    pdr, OGS_GTPU_MSGTYPE_GPDU, 0, NULL, sendbuf, &report));
        ogs_debug("[UPF-TAP] Sent synthetic Router Advertisement to UE");
        break;
    }

    ogs_pkbuf_free(pkbuf);
}

void upf_gtp_announce_subscriber(upf_sess_t *sess)
{
    ogs_pfcp_subnet_t *subnet = NULL;
    ogs_pfcp_dev_t *dev = NULL;
    ogs_pkbuf_t *pkbuf = NULL;
    uint8_t size;
    static const uint8_t zero_mac[ETHER_ADDR_LEN] = {0};
    const uint8_t *announce_mac;

    ogs_assert(sess);

    announce_mac = (memcmp(sess->imeisv_mac_addr, zero_mac, ETHER_ADDR_LEN) != 0) ?
            sess->imeisv_mac_addr : proxy_mac_addr;

    if (sess->ipv4) {
        subnet = sess->ipv4->subnet;
        if (subnet && subnet->dev && subnet->dev->is_tap) {
            dev = subnet->dev;
            pkbuf = ogs_pkbuf_alloc(packet_pool, OGS_MAX_PKT_LEN);
            ogs_assert(pkbuf);
            ogs_pkbuf_reserve(pkbuf, OGS_TUN_MAX_HEADROOM);
            ogs_pkbuf_put(pkbuf, OGS_MAX_PKT_LEN - OGS_TUN_MAX_HEADROOM);
            size = garp_build(pkbuf->data,
                    (const uint8_t *)sess->ipv4->addr, announce_mac);
            if (size > 0) {
                char buf[OGS_ADDRSTRLEN];
                ogs_pkbuf_trim(pkbuf, size);
                if (ogs_tun_write(dev->fd, pkbuf) != OGS_OK)
                    ogs_warn("gratuitous ARP write failed");
                else
                    ogs_info("[%s] GARP sent for UE IP [%s] MAC "
                        "%02x:%02x:%02x:%02x:%02x:%02x",
                        dev->ifname,
                        OGS_INET_NTOP(sess->ipv4->addr, buf),
                        announce_mac[0], announce_mac[1], announce_mac[2],
                        announce_mac[3], announce_mac[4], announce_mac[5]);
            }
            ogs_pkbuf_free(pkbuf);

            /*
             * Immediately follow the GARP with a proper ARP who-has for the
             * gateway, using the UE IP as sender_ip.  The startup probe uses
             * sender_ip=0.0.0.0 (RFC 5227) which many gateways silently ignore.
             * A who-has with a real sender IP guarantees a unicast reply that
             * teaches us the gateway MAC before any downlink traffic arrives.
             */
            if (subnet->gw.family == AF_INET) {
                char buf[OGS_ADDRSTRLEN];
                pkbuf = ogs_pkbuf_alloc(packet_pool, OGS_MAX_PKT_LEN);
                ogs_assert(pkbuf);
                ogs_pkbuf_reserve(pkbuf, OGS_TUN_MAX_HEADROOM);
                ogs_pkbuf_put(pkbuf, OGS_MAX_PKT_LEN - OGS_TUN_MAX_HEADROOM);
                size = arp_who_has_build(pkbuf->data,
                        (const uint8_t *)subnet->gw.sub,
                        (const uint8_t *)sess->ipv4->addr,
                        announce_mac);
                if (size > 0) {
                    ogs_pkbuf_trim(pkbuf, size);
                    if (ogs_tun_write(dev->fd, pkbuf) != OGS_OK)
                        ogs_warn("gateway ARP who-has write failed");
                    else
                        ogs_debug("[%s] ARP who-has sent for gateway [%s]",
                            dev->ifname,
                            OGS_INET_NTOP(&subnet->gw.sub, buf));
                }
                ogs_pkbuf_free(pkbuf);
            }
        }
    }

    if (sess->ipv6) {
        subnet = sess->ipv6->subnet;
        if (subnet && subnet->dev && subnet->dev->is_tap) {
            dev = subnet->dev;
            /*
             * Send a Neighbor Solicitation to the IPv6 gateway to proactively
             * learn its MAC address (gw6_mac_addr) before downlink traffic arrives.
             * This mirrors the IPv4 ARP Who-Has behavior above.
             *
             * The NS is sent from a link-local address derived from the UE's MAC
             * (via EUI-64 in ns_request_build()) and targets the gateway's IPv6
             * address.  The gateway will reply with a unicast Neighbor Advertisement
             * containing its MAC, which will be learned by the TAP receive path.
             */
            if (subnet->gw.family == AF_INET6) {
                char buf[OGS_ADDRSTRLEN];
                pkbuf = ogs_pkbuf_alloc(packet_pool, OGS_MAX_PKT_LEN);
                ogs_assert(pkbuf);
                ogs_pkbuf_reserve(pkbuf, OGS_TUN_MAX_HEADROOM);
                ogs_pkbuf_put(pkbuf, OGS_MAX_PKT_LEN - OGS_TUN_MAX_HEADROOM);
                size = ns_request_build(pkbuf->data,
                        (const uint8_t *)subnet->gw.sub,
                        announce_mac);
                if (size > 0) {
                    ogs_pkbuf_trim(pkbuf, size);
                    if (ogs_tun_write(dev->fd, pkbuf) != OGS_OK)
                        ogs_warn("gateway IPv6 NS write failed");
                    else
                        ogs_debug("[%s] IPv6 NS sent for gateway [%s]",
                            dev->ifname,
                            OGS_INET6_NTOP(subnet->gw.sub, buf));
                }
                ogs_pkbuf_free(pkbuf);
            }
        }
    }

}

static int check_framed_routes(upf_sess_t *sess, int family, uint32_t *addr)
{
    int i = 0;
    ogs_ipsubnet_t *routes = family == AF_INET ?
        sess->ipv4_framed_routes : sess->ipv6_framed_routes;

    if (!routes)
        return false;

    for (i = 0; i < OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI; i++) {
        uint32_t *sub = routes[i].sub;
        uint32_t *mask = routes[i].mask;

        if (!routes[i].family)
            break;

        if (family == AF_INET) {
            if (sub[0] == (addr[0] & mask[0]))
                return true;
        } else {
            if (sub[0] == (addr[0] & mask[0]) &&
                sub[1] == (addr[1] & mask[1]) &&
                sub[2] == (addr[2] & mask[2]) &&
                sub[3] == (addr[3] & mask[3]))
                return true;
        }
    }
    return false;
}

static uint16_t _get_eth_type(uint8_t *data, uint len) {
    if (len > ETHER_HDR_LEN) {
        struct ether_header *hdr = (struct ether_header*)data;
        return htobe16(hdr->ether_type);
    }
    return 0;
}

static void _gtpv1_tun_recv_common_cb(
        short when, ogs_socket_t fd, bool has_eth, void *data)
{
    ogs_pkbuf_t *recvbuf = NULL;

    upf_sess_t *sess = NULL;
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_pdr_t *fallback_pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_user_plane_report_t report;
    ogs_pfcp_dev_t *tap_dev = NULL;
    int i;

    recvbuf = ogs_tun_read(fd, packet_pool);
    if (!recvbuf) {
        ogs_warn("ogs_tun_read() failed");
        return;
    }

    if (has_eth) {
        ogs_pkbuf_t *replybuf = NULL;
        uint16_t eth_type = _get_eth_type(recvbuf->data, recvbuf->len);
        uint8_t size;
        ogs_list_for_each(&ogs_pfcp_self()->dev_list, tap_dev) {
            if (tap_dev->fd == fd) break;
        }

        /*
         * Learn the gateway MAC from the source address of every unicast
         * frame arriving on the TAP. This is used as the Ethernet destination
         * when forwarding UE uplink packets back toward the gateway.
         */
        if (tap_dev && recvbuf->len >= ETHER_HDR_LEN) {
            const uint8_t *src_mac =
                    (const uint8_t *)recvbuf->data + ETHER_ADDR_LEN;
            if (!(src_mac[0] & 0x01) &&
                    memcmp(src_mac, proxy_mac_addr, ETHER_ADDR_LEN) != 0) {
                /*
                 * Track IPv4 and IPv6 gateway MACs independently:
                 * the two gateways may be different devices.
                 */
                if (eth_type == ETHERTYPE_IP ||
                        eth_type == ETHERTYPE_ARP) {
                    if (memcmp(tap_dev->gw_mac_addr,
                            src_mac, ETHER_ADDR_LEN) != 0) {
                        memcpy(tap_dev->gw_mac_addr,
                                src_mac, ETHER_ADDR_LEN);
                        ogs_info("[%s] learned IPv4 gateway MAC "
                            "%02x:%02x:%02x:%02x:%02x:%02x",
                            tap_dev->ifname,
                            src_mac[0], src_mac[1], src_mac[2],
                            src_mac[3], src_mac[4], src_mac[5]);
                    }
                } else if (eth_type == ETHERTYPE_IPV6) {
                    /*
                     * Only trust ICMPv6 ND messages as authoritative
                     * sources for the gateway MAC.  Learning from
                     * arbitrary IPv6 traffic causes the wrong MAC to be
                     * recorded transiently at startup when frames from
                     * other on-link hosts arrive before the first RA or
                     * NA from the actual router.
                     *
                     *  - Router Advertisement (type 134): always sent
                     *    by a router; its source MAC is the router MAC.
                     *  - Neighbor Advertisement (type 136): accept only
                     *    when the NA target address matches a configured
                     *    IPv6 gateway on this TAP device, so we learn
                     *    from solicited NA replies to our NS probes and
                     *    not from unsolicited NAs sent by other hosts.
                     */
                    bool learn_ipv6_mac = false;
                    if (recvbuf->len >= (int)(ETHER_HDR_LEN +
                            sizeof(struct ip6_hdr) +
                            sizeof(struct icmp6_hdr))) {
                        const struct ip6_hdr *ip6_lrn =
                            (const struct ip6_hdr *)
                            ((const uint8_t *)recvbuf->data +
                             ETHER_HDR_LEN);
                        if (ip6_lrn->ip6_nxt == IPPROTO_ICMPV6) {
                            const struct icmp6_hdr *icmp6_lrn =
                                (const struct icmp6_hdr *)
                                ((const uint8_t *)recvbuf->data +
                                 ETHER_HDR_LEN + sizeof(*ip6_lrn));
                            if (icmp6_lrn->icmp6_type ==
                                    ND_ROUTER_ADVERT) {
                                learn_ipv6_mac = true;
                            } else if (icmp6_lrn->icmp6_type ==
                                    ND_NEIGHBOR_ADVERT &&
                                    recvbuf->len >= (int)(
                                    ETHER_HDR_LEN +
                                    sizeof(struct ip6_hdr) +
                                    sizeof(struct nd_neighbor_advert)))
                            {
                                const struct nd_neighbor_advert *na =
                                    (const struct nd_neighbor_advert *)
                                    icmp6_lrn;
                                ogs_pfcp_subnet_t *sn = NULL;
                                ogs_list_for_each(
                                        &ogs_pfcp_self()->subnet_list,
                                        sn) {
                                    if (sn->dev != tap_dev ||
                                            sn->family != AF_INET6 ||
                                            !sn->gw.family)
                                        continue;
                                    if (memcmp(
                                            na->nd_na_target.s6_addr,
                                            sn->gw.sub, 16) == 0) {
                                        learn_ipv6_mac = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if (learn_ipv6_mac &&
                            memcmp(tap_dev->gw6_mac_addr,
                                    src_mac, ETHER_ADDR_LEN) != 0) {
                        memcpy(tap_dev->gw6_mac_addr,
                                src_mac, ETHER_ADDR_LEN);
                        ogs_info("[%s] learned IPv6 gateway MAC "
                            "%02x:%02x:%02x:%02x:%02x:%02x",
                            tap_dev->ifname,
                            src_mac[0], src_mac[1], src_mac[2],
                            src_mac[3], src_mac[4], src_mac[5]);
                    }
                }
            }
        }

        if (eth_type == ETHERTYPE_ARP) {
            upf_sess_t *arp_sess = NULL;
            if (is_arp_req(recvbuf->data, recvbuf->len)) {
                uint32_t target_ip =
                        arp_parse_target_addr(recvbuf->data, recvbuf->len);
                char buf[OGS_ADDRSTRLEN];
                ogs_debug("[RECV] ARP request for UE IP [%s]",
                    OGS_INET_NTOP(&target_ip, buf));
                arp_sess = upf_sess_find_by_ipv4(target_ip);
                /* Reject sessions homed on a different TAP device */
                if (arp_sess && (!tap_dev || !arp_sess->ipv4 ||
                        !arp_sess->ipv4->subnet ||
                        arp_sess->ipv4->subnet->dev != tap_dev))
                    arp_sess = NULL;
            }
            if (arp_sess) {
                static const uint8_t zero_mac_arp[ETHER_ADDR_LEN] = {0};
                const uint8_t *reply_mac =
                        (memcmp(arp_sess->imeisv_mac_addr,
                                zero_mac_arp, ETHER_ADDR_LEN) != 0) ?
                        arp_sess->imeisv_mac_addr : proxy_mac_addr;
                replybuf = ogs_pkbuf_alloc(packet_pool, OGS_MAX_PKT_LEN);
                ogs_assert(replybuf);
                ogs_pkbuf_reserve(replybuf, OGS_TUN_MAX_HEADROOM);
                ogs_pkbuf_put(replybuf, OGS_MAX_PKT_LEN-OGS_TUN_MAX_HEADROOM);
                size = arp_reply(replybuf->data, recvbuf->data, recvbuf->len,
                    reply_mac);
                ogs_pkbuf_trim(replybuf, size);
                ogs_debug("[SEND] ARP reply for UE IP: MAC "
                    "%02x:%02x:%02x:%02x:%02x:%02x",
                    reply_mac[0], reply_mac[1], reply_mac[2],
                    reply_mac[3], reply_mac[4], reply_mac[5]);
            } else {
                goto cleanup;
            }
        } else if (eth_type == ETHERTYPE_IPV6 &&
                    is_nd_req(recvbuf->data, recvbuf->len)) {
            uint8_t nd_target[16];
            upf_sess_t *nd_sess = NULL;
            if (nd_parse_target_addr(recvbuf->data, recvbuf->len, nd_target)) {
                char buf[OGS_ADDRSTRLEN];
                ogs_debug("[RECV] NS request for UE IP [%s]",
                    OGS_INET6_NTOP(nd_target, buf));
                nd_sess = upf_sess_find_by_ipv6((uint32_t *)nd_target);
                /* Reject sessions homed on a different TAP device */
                if (nd_sess && (!tap_dev || !nd_sess->ipv6 ||
                        !nd_sess->ipv6->subnet ||
                        nd_sess->ipv6->subnet->dev != tap_dev))
                    nd_sess = NULL;
            }
            if (nd_sess) {
                static const uint8_t zero_mac_nd[ETHER_ADDR_LEN] = {0};
                const uint8_t *reply_mac =
                        (memcmp(nd_sess->imeisv_mac_addr,
                                zero_mac_nd, ETHER_ADDR_LEN) != 0) ?
                        nd_sess->imeisv_mac_addr : proxy_mac_addr;
                replybuf = ogs_pkbuf_alloc(packet_pool, OGS_MAX_PKT_LEN);
                ogs_assert(replybuf);
                ogs_pkbuf_reserve(replybuf, OGS_TUN_MAX_HEADROOM);
                ogs_pkbuf_put(replybuf, OGS_MAX_PKT_LEN-OGS_TUN_MAX_HEADROOM);
                size = nd_reply(replybuf->data, recvbuf->data, recvbuf->len,
                    reply_mac);
                ogs_pkbuf_trim(replybuf, size);
                ogs_debug("[SEND] NS reply for UE IP: MAC "
                    "%02x:%02x:%02x:%02x:%02x:%02x",
                    reply_mac[0], reply_mac[1], reply_mac[2],
                    reply_mac[3], reply_mac[4], reply_mac[5]);
            } else {
                goto cleanup;
            }
        }
        if (replybuf) {
            if (ogs_tun_write(fd, replybuf) != OGS_OK)
                ogs_warn("ogs_tun_write() for reply failed");

            ogs_pkbuf_free(replybuf);
            goto cleanup;
        }
        if (eth_type != ETHERTYPE_IP && eth_type != ETHERTYPE_IPV6) {
            // Drop LLDP and any 802.3 frames as we don't care about this on the EPC side
            // Generate a warning on any other packets we don't understand
            // LLDP = 0x88CC EtherType
            // 802.3 Frame = EtherType < 0x05DC
            if (eth_type != 0x88CC && eth_type > 0x05DC) {
                ogs_warn("[DROP] Invalid eth_type [%x]]", eth_type);
            }
            goto cleanup;
        }
        ogs_pkbuf_pull(recvbuf, ETHER_HDR_LEN);

        /*
         * In TAP mode, Router Advertisements (and other IPv6 multicast
         * control traffic from the upstream router) arrive with a destination
         * of ff02::1 (all-nodes), which is not in the per-session IPv6 hash
         * (keyed by global /64 prefix).  Deliver multicast to every IPv6 UE
         * on this TAP device.
         *
         * Link-local unicast is dropped: RSes are intercepted uplink and
         * answered with a synthetic RA, and NS for fe80::1 are intercepted
         * uplink and answered with a synthetic NA, so the real router never
         * sends link-local unicast toward a UE.
         */
        if (tap_dev) {
            struct ip *ip_h_chk = (struct ip *)recvbuf->data;
            if (ip_h_chk->ip_v == 6 &&
                    recvbuf->len >= sizeof(struct ip6_hdr)) {
                struct ip6_hdr *ip6_h_chk =
                        (struct ip6_hdr *)recvbuf->data;
                struct in6_addr ip6_dst;
                memcpy(&ip6_dst, &ip6_h_chk->ip6_dst, sizeof(ip6_dst));

                if (IN6_IS_ADDR_MULTICAST(&ip6_dst)) {
                    /* e.g. Router Advertisement to ff02::1 */
                    upf_gtp_handle_tap_ipv6_mcast(recvbuf, tap_dev);
                    goto cleanup;
                } else if (IN6_IS_ADDR_LINKLOCAL(&ip6_dst)) {
                    /* Drop: all link-local unicast is handled synthetically. */
                    goto cleanup;
                }
            }
        }
    }

    if (!sess) {
        sess = upf_sess_find_by_ue_ip_address(recvbuf);
        if (!sess)
            goto cleanup;
    }

    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        far = pdr->far;
        ogs_assert(far);

        /* Check if PDR is Downlink */
        if (pdr->src_if != OGS_PFCP_INTERFACE_CORE)
            continue;

        /* Save the Fallback PDR : Lowest precedence downlink PDR */
        fallback_pdr = pdr;

        /* Check if FAR is Downlink */
        if (far->dst_if != OGS_PFCP_INTERFACE_ACCESS)
            continue;

        /* Check if Outer header creation */
        if (far->outer_header_creation.ip4 == 0 &&
            far->outer_header_creation.ip6 == 0 &&
            far->outer_header_creation.udp4 == 0 &&
            far->outer_header_creation.udp6 == 0 &&
            far->outer_header_creation.gtpu4 == 0 &&
            far->outer_header_creation.gtpu6 == 0)
            continue;

        /* Check if Rule List in PDR */
        if (ogs_list_first(&pdr->rule_list) &&
            ogs_pfcp_pdr_rule_find_by_packet(pdr, recvbuf) == NULL)
            continue;

        break;
    }

    if (!pdr)
        pdr = fallback_pdr;

    if (!pdr) {
        if (ogs_global_conf()->parameter.multicast) {
            upf_gtp_handle_multicast(recvbuf);
        }
        goto cleanup;
    }

    /* Increment total & dl octets + pkts */
    for (i = 0; i < pdr->num_of_urr; i++)
        upf_sess_urr_acc_add(sess, pdr->urr[i], recvbuf->len, false);

    ogs_assert(true == ogs_pfcp_up_handle_pdr(
                pdr, OGS_GTPU_MSGTYPE_GPDU, 0, NULL, recvbuf, &report));

    /*
     * Issue #2210, Discussion #2208, #2209
     *
     * Metrics reduce data plane performance.
     * It should not be used on the UPF/SGW-U data plane
     * until this issue is resolved.
     */
#if 0
    upf_metrics_inst_global_inc(UPF_METR_GLOB_CTR_GTP_OUTDATAPKTN3UPF);
    upf_metrics_inst_by_qfi_add(pdr->qer->qfi,
        UPF_METR_CTR_GTP_OUTDATAVOLUMEQOSLEVELN3UPF, recvbuf->len);
#endif

    if (report.type.downlink_data_report) {
        ogs_assert(pdr->sess);
        sess = UPF_SESS(pdr->sess);
        ogs_assert(sess);

        report.downlink_data.pdr_id = pdr->id;
        if (pdr->qer && pdr->qer->qfi)
            report.downlink_data.qfi = pdr->qer->qfi; /* for 5GC */

        ogs_assert(OGS_OK ==
            upf_pfcp_send_session_report_request(sess, &report));
    }

    /*
     * The ogs_pfcp_up_handle_pdr() function
     * buffers or frees the Packet Buffer(pkbuf) memory.
     */
    return;

cleanup:
    ogs_pkbuf_free(recvbuf);
}

static void _gtpv1_tun_recv_cb(short when, ogs_socket_t fd, void *data)
{
    _gtpv1_tun_recv_common_cb(when, fd, false, data);
}

static void _gtpv1_tun_recv_eth_cb(short when, ogs_socket_t fd, void *data)
{
    _gtpv1_tun_recv_common_cb(when, fd, true, data);
}

static void _gtpv1_u_recv_cb(short when, ogs_socket_t fd, void *data)
{
    int len;
    ssize_t size;
    char buf1[OGS_ADDRSTRLEN];
    char buf2[OGS_ADDRSTRLEN];

    upf_sess_t *sess = NULL;

    ogs_pkbuf_t *pkbuf = NULL;
    ogs_sock_t *sock = NULL;
    ogs_sockaddr_t from;

    ogs_gtp2_header_t *gtp_h = NULL;
    ogs_gtp2_header_desc_t header_desc;
    ogs_pfcp_user_plane_report_t report;

    ogs_assert(fd != INVALID_SOCKET);
    sock = data;
    ogs_assert(sock);

    pkbuf = ogs_pkbuf_alloc(packet_pool, OGS_MAX_PKT_LEN);
    ogs_assert(pkbuf);
    ogs_pkbuf_reserve(pkbuf, OGS_TUN_MAX_HEADROOM);
    ogs_pkbuf_put(pkbuf, OGS_MAX_PKT_LEN-OGS_TUN_MAX_HEADROOM);

    size = ogs_recvfrom(fd, pkbuf->data, pkbuf->len, 0, &from);
    if (size <= 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "ogs_recv() failed");
        goto cleanup;
    }

    ogs_pkbuf_trim(pkbuf, size);

    ogs_assert(pkbuf);
    ogs_assert(pkbuf->len);

    gtp_h = (ogs_gtp2_header_t *)pkbuf->data;
    if (gtp_h->version != OGS_GTP2_VERSION_1) {
        ogs_error("[DROP] Invalid GTPU version [%d]", gtp_h->version);
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        goto cleanup;
    }

    len = ogs_gtpu_parse_header(&header_desc, pkbuf);
    if (len < 0) {
        ogs_error("[DROP] Cannot decode GTPU packet");
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        goto cleanup;
    }
    if (header_desc.type == OGS_GTPU_MSGTYPE_ECHO_REQ) {
        ogs_pkbuf_t *echo_rsp;

        ogs_info("[RECV] Echo Request from [%s]", OGS_ADDR(&from, buf1));
        echo_rsp = ogs_gtp2_handle_echo_req(pkbuf);
        ogs_expect(echo_rsp);
        if (echo_rsp) {
            ssize_t sent;

            /* Echo reply */
            ogs_info("[SEND] Echo Response to [%s]", OGS_ADDR(&from, buf1));

            sent = ogs_sendto(fd, echo_rsp->data, echo_rsp->len, 0, &from);
            if (sent < 0 || sent != echo_rsp->len) {
                ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                        "ogs_sendto() failed");
            }
            ogs_pkbuf_free(echo_rsp);
        }
        goto cleanup;
    }
    if (header_desc.type != OGS_GTPU_MSGTYPE_END_MARKER &&
        pkbuf->len <= len) {
        ogs_error("[DROP] Small GTPU packet(type:%d len:%d)",
                header_desc.type, len);
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        goto cleanup;
    }

    ogs_trace("[RECV] GPU-U Type [%d] from [%s] : TEID[0x%x]",
            header_desc.type, OGS_ADDR(&from, buf1), header_desc.teid);

    /* Remove GTP header and send packets to TUN interface */
    ogs_assert(ogs_pkbuf_pull(pkbuf, len));

    if (header_desc.type == OGS_GTPU_MSGTYPE_END_MARKER) {
        /* Nothing */

    } else if (header_desc.type == OGS_GTPU_MSGTYPE_ERR_IND) {
        ogs_pfcp_far_t *far = NULL;

        far = ogs_pfcp_far_find_by_gtpu_error_indication(pkbuf);
        if (far) {
            ogs_assert(true ==
                ogs_pfcp_up_handle_error_indication(far, &report));

            if (report.type.error_indication_report) {
                ogs_assert(far->sess);
                sess = UPF_SESS(far->sess);
                ogs_assert(sess);

                ogs_assert(OGS_OK ==
                    upf_pfcp_send_session_report_request(sess, &report));
            }

        } else {
            ogs_error("[DROP] Cannot find FAR by Error-Indication");
            ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        }
    } else if (header_desc.type == OGS_GTPU_MSGTYPE_GPDU) {
        uint16_t eth_type = 0;
        struct ip *ip_h = NULL;
        uint32_t *src_addr = NULL;
        ogs_pfcp_object_t *pfcp_object = NULL;
        ogs_pfcp_sess_t *pfcp_sess = NULL;
        ogs_pfcp_pdr_t *pdr = NULL;
        ogs_pfcp_far_t *far = NULL;

        ogs_pfcp_subnet_t *subnet = NULL;
        ogs_pfcp_dev_t *dev = NULL;
        int i;

        ip_h = (struct ip *)pkbuf->data;
        ogs_assert(ip_h);

        /*
         * Issue #2210, Discussion #2208, #2209
         *
         * Metrics reduce data plane performance.
         * It should not be used on the UPF/SGW-U data plane
         * until this issue is resolved.
         */
#if 0
        upf_metrics_inst_global_inc(UPF_METR_GLOB_CTR_GTP_INDATAPKTN3UPF);
        upf_metrics_inst_by_qfi_add(header_desc.qos_flow_identifier,
                UPF_METR_CTR_GTP_INDATAVOLUMEQOSLEVELN3UPF, pkbuf->len);
#endif

        pfcp_object = ogs_pfcp_object_find_by_teid(header_desc.teid);
        if (!pfcp_object) {
            /*
             * TS23.527 Restoration procedures
             * 4.3 UPF Restoration Procedures
             * 4.3.2 Restoration Procedure for PSA UPF Restart
             *
             * The UPF shall not send GTP-U Error indication message
             * for a configurable period after an UPF restart
             * when the UPF receives a G-PDU not matching any PDRs.
             */
            if (ogs_time_ntp32_now() >
                   (ogs_pfcp_self()->local_recovery +
                    ogs_time_sec(ogs_local_conf()->time.message.pfcp.
                        association_interval))) {
                ogs_error("[%s] Send Error Indication [TEID:0x%x] to [%s]",
                        OGS_ADDR(&sock->local_addr, buf1),
                        header_desc.teid,
                        OGS_ADDR(&from, buf2));
                ogs_gtp1_send_error_indication(
                        sock, header_desc.teid,
                        header_desc.qos_flow_identifier, &from);
            }
            goto cleanup;
        }

        switch(pfcp_object->type) {
        case OGS_PFCP_OBJ_PDR_TYPE:
            /* UPF does not use PDR TYPE */
            ogs_assert_if_reached();
            pdr = (ogs_pfcp_pdr_t *)pfcp_object;
            ogs_assert(pdr);
            break;
        case OGS_PFCP_OBJ_SESS_TYPE:
            pfcp_sess = (ogs_pfcp_sess_t *)pfcp_object;
            ogs_assert(pfcp_sess);

            ogs_list_for_each(&pfcp_sess->pdr_list, pdr) {

                /*
                 * Originally, we checked the Source Interface
                 * for packets received with a TEID.
                 *
                 * However, in the case of Home Routed Roaming,
                 * packets arriving at the V-UPF from the Core
                 * do not come through a TUN interface
                 * but as standard GTP-U packets.
                 *
                 * Therefore, this code has been removed to support
                 * the roaming functionality.
                 */
#if 0 /* <DEPRECATED> */
                if (pdr->src_if != OGS_PFCP_INTERFACE_ACCESS &&
                    pdr->src_if != OGS_PFCP_INTERFACE_CP_FUNCTION)
                    continue;
#endif

                /* Check if TEID */
                if (header_desc.teid != pdr->f_teid.teid)
                    continue;

                /* Check if QFI */
                if (pdr->qfi && pdr->qfi != header_desc.qos_flow_identifier)
                    continue;

                /* Check if Rule List in PDR */
                if (ogs_list_first(&pdr->rule_list) &&
                    ogs_pfcp_pdr_rule_find_by_packet(pdr, pkbuf) == NULL)
                    continue;

                break;
            }

            if (!pdr) {
                /*
                 * TS23.527 Restoration procedures
                 * 4.3 UPF Restoration Procedures
                 * 4.3.2 Restoration Procedure for PSA UPF Restart
                 *
                 * The UPF shall not send GTP-U Error indication message
                 * for a configurable period after an UPF restart
                 * when the UPF receives a G-PDU not matching any PDRs.
                 */
                if (ogs_time_ntp32_now() >
                       (ogs_pfcp_self()->local_recovery +
                        ogs_time_sec(ogs_local_conf()->time.message.pfcp.
                            association_interval))) {
                    ogs_error(
                            "[%s] Send Error Indication [TEID:0x%x] to [%s]",
                            OGS_ADDR(&sock->local_addr, buf1),
                            header_desc.teid,
                            OGS_ADDR(&from, buf2));
                    ogs_gtp1_send_error_indication(
                            sock, header_desc.teid,
                            header_desc.qos_flow_identifier, &from);
                }
                goto cleanup;
            }

            break;
        default:
            ogs_fatal("Unknown type [%d]", pfcp_object->type);
            ogs_assert_if_reached();
        }

        ogs_assert(pdr);
        ogs_assert(pdr->sess);
        ogs_assert(pdr->sess->obj.type == OGS_PFCP_OBJ_SESS_TYPE);

        sess = UPF_SESS(pdr->sess);
        ogs_assert(sess);

        far = pdr->far;
        ogs_assert(far);

        /*
         * In TAP mode the up2cp PDR (precedence=255) steals Router
         * Solicitations before the ul_pdr (precedence=65535) can match them.
         * This happens because the SDF filter "permit out 58 from
         * ff02::2/128 to assigned" compiles "assigned" → "any", and after
         * the uplink src/dst swap the rule becomes (src=any, dst=ff02::2,
         * proto=58), which matches the RS perfectly.
         *
         * Forwarding the RS to the real router creates two problems:
         *  1. If the router sends a solicited RA unicast to the UE's fe80::
         *     link-local, upf_gtp_handle_tap_ipv6_mcast() broadcasts it to
         *     every IPv6 UE on the TAP instead of only the requesting UE.
         *  2. The UPF already knows the UE's /64 prefix, so there is no need
         *     to involve the real router at all.
         *
         * Instead, generate a synthetic RA directly and deliver it to the UE
         * via its downlink GTP-U tunnel.  This mirrors the SMF behaviour in
         * non-TAP mode (send_router_advertisement() in smf/gtp-path.c).
         */
        if (far->dst_if == OGS_PFCP_INTERFACE_CP_FUNCTION) {
            ogs_pfcp_subnet_t *tap_sub =
                (sess->ipv6 && sess->ipv6->subnet) ? sess->ipv6->subnet :
                (sess->ipv4 && sess->ipv4->subnet) ? sess->ipv4->subnet : NULL;
            if (tap_sub && tap_sub->dev && tap_sub->dev->is_tap &&
                    sess->ipv6 && _check_router_solicit(pkbuf)) {
                struct ip6_hdr *ip6_h = (struct ip6_hdr *)pkbuf->data;
                _send_router_advertisement(sess, ip6_h->ip6_src.s6_addr);
                goto cleanup;
            }
        }

        /*
         * From Issue #1354
         *
         * Do not check Router Advertisement
         *    pdr->src_if = OGS_PFCP_INTERFACE_CP_FUNCTION;
         *    far->dst_if = OGS_PFCP_INTERFACE_ACCESS;
         *
         * Do not check Indirect Tunnel
         *    pdr->dst_if = OGS_PFCP_INTERFACE_ACCESS;
         *    far->dst_if = OGS_PFCP_INTERFACE_ACCESS;
         */

        /*
         * The implementation was initially based on Issue #1354,
         * where the system was designed not to perform checks
         * when FAR->dst_if was set to ACCESS.
         *
         * However, this has now been updated
         * to a new approach that checks for IP source spoofing
         * only when PDR->src_if is set to ACCESS.
         *
         * That said, for Home Routed Roaming scenarios, the system skips
         * this process during uplink traffic, as the V-UPF does not hold
         * IP address information in such cases.
         *
         * <Normal>
         * o DL
         *  PDR->src : Core/N6
         *  FAT->dst : Access/N3
         * o UL
         *  PDR->src : Access/N3
         *  FAT->dst : Core/N6
         * o CP2UP
         *  PDR->src : CP-function
         *  FAT->dst : Access/N3
         * o UP2CP
         *  PDR->src : Access/N3
         *  FAT->dst : CP-function
         *
         * <Indirect>
         *  PDR->src : Access/UL-Forwarding
         *  FAT->dst : Access/DL-Forwarding
         *
         * <Home Routed Roaming>
         * - VPLMN
         * o DL
         *  PDR->src : Core/N9-for-roaming
         *  FAT->dst : Access/N3
         * o UL
         *  PDR->src : Access/N3
         *  FAT->dst : Core/N9-for-roaming
         * - HPLMN
         * o DL
         *  PDR->src : Core/N6
         *  FAT->dst : Access/N9-for-roaming
         * o UL
         *  PDR->src : Access/N9-for-roaming
         *  FAT->dst : Core/N6
         */

        /*
         * We first verify whether the Source Interface of the PDR is set
         * to ACCESS and if it corresponds to N3 3GPP ACCESS.
         *
         * This is because IP source spoofing checks are performed only
         * in such cases.
         */
        if (pdr->src_if == OGS_PFCP_INTERFACE_ACCESS &&
            pdr->src_if_type_presence == true &&
            (pdr->src_if_type == OGS_PFCP_3GPP_INTERFACE_TYPE_N3_3GPP_ACCESS ||
             pdr->src_if_type == OGS_PFCP_3GPP_INTERFACE_TYPE_N9_FOR_ROAMING)) {

            if (far->dst_if_type_presence == true &&
                far->dst_if_type ==
                    OGS_PFCP_3GPP_INTERFACE_TYPE_N9_FOR_ROAMING) {
                /*
                 * <SKIP>
                 *
                 * However, Home Routed Roaming is excluded from this check,
                 * as the V-UPF does not have the necessary IP address
                 * information to perform the verification.
                 */

            } else if (ip_h->ip_v == 4 && sess->ipv4) {
                src_addr = (void *)&ip_h->ip_src.s_addr;
                ogs_assert(src_addr);

                if (src_addr[0] == sess->ipv4->addr[0]) {
                    /* Source IP address should be matched in uplink */
                } else if (check_framed_routes(sess, AF_INET, src_addr)) {
                    /* Or source IP address should match a framed route */
                } else {
                    ogs_error("[DROP] Source IP-%d Spoofing APN:%s SrcIf:%d DstIf:%d TEID:0x%x",
                                ip_h->ip_v, pdr->dnn, pdr->src_if, far->dst_if, header_desc.teid);
                    ogs_error("       SRC:%08X, UE:%08X",
                        be32toh(src_addr[0]), be32toh(sess->ipv4->addr[0]));
                    ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);

                    goto cleanup;
                }

                subnet = sess->ipv4->subnet;
                eth_type = ETHERTYPE_IP;

            } else if (ip_h->ip_v == 6 && sess->ipv6) {
                struct ip6_hdr *ip6_h = (struct ip6_hdr *)pkbuf->data;
                ogs_assert(ip6_h);
                src_addr = (void *)ip6_h->ip6_src.s6_addr;
                ogs_assert(src_addr);

    /*
     * Discussion #1776 was raised,
     * but we decided not to allow unspecified addresses
     * because Open5GS has already sent interface identifiers
     * in the registgration/attach process.
     *
     *
     * RFC4861
     * 4.  Message Formats
     * 4.1.  Router Solicitation Message Format
     * IP Fields:
     *    Source Address
     *                  An IP address assigned to the sending interface, or
     *                  the unspecified address if no address is assigned
     *                  to the sending interface.
     *
     * 6.1.  Message Validation
     * 6.1.1.  Validation of Router Solicitation Messages
     *  Hosts MUST silently discard any received Router Solicitation
     *  Messages.
     *
     *  A router MUST silently discard any received Router Solicitation
     *  messages that do not satisfy all of the following validity checks:
     *
     *  ..
     *  ..
     *
     *  - If the IP source address is the unspecified address, there is no
     *    source link-layer address option in the message.
     */
                if (IN6_IS_ADDR_LINKLOCAL((struct in6_addr *)src_addr)) {
                    /*
                     * Link-local source (e.g. Router Solicitation fe80::<IID>):
                     * allow any link-local.  The GTP TEID already authenticates
                     * which UE sent this packet; the IID match is not required
                     * because the UE may derive its own IID rather than using
                     * the network-assigned one from the PDN context.
                     */
                } else if (src_addr[0] == sess->ipv6->addr[0] &&
                            src_addr[1] == sess->ipv6->addr[1]) {
                    /*
                     * If Global address
                     * 64 bit prefix should be matched
                     */
                } else if (check_framed_routes(sess, AF_INET6, src_addr)) {
                    /* Or source IP address should match a framed route */
                } else {
                    ogs_error("[DROP] Source IP-%d Spoofing APN:%s SrcIf:%d DstIf:%d TEID:0x%x",
                                ip_h->ip_v, pdr->dnn, pdr->src_if, far->dst_if, header_desc.teid);
                    ogs_error("SRC:%08x %08x %08x %08x",
                            be32toh(src_addr[0]), be32toh(src_addr[1]),
                            be32toh(src_addr[2]), be32toh(src_addr[3]));
                    ogs_error("UE:%08x %08x %08x %08x",
                            be32toh(sess->ipv6->addr[0]),
                            be32toh(sess->ipv6->addr[1]),
                            be32toh(sess->ipv6->addr[2]),
                            be32toh(sess->ipv6->addr[3]));
                    ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);

                    goto cleanup;
                }

                subnet = sess->ipv6->subnet;
                eth_type = ETHERTYPE_IPV6;

            } else {
                ogs_error("Invalid packet [IP version:%d, Packet Length:%d]",
                        ip_h->ip_v, pkbuf->len);
                ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
                goto cleanup;
            }

        }

        if (far->dst_if == OGS_PFCP_INTERFACE_CORE &&
            far->dst_if_type_presence == true &&
            far->dst_if_type == OGS_PFCP_3GPP_INTERFACE_TYPE_N6) {

            upf_sess_t *dst_sess = NULL;
            ogs_pfcp_pdr_t *dl_pdr = NULL;
            ogs_pfcp_pdr_t *dl_fallback_pdr = NULL;
            ogs_pfcp_far_t *dl_far = NULL;
            ogs_pfcp_user_plane_report_t dl_report;

            if (!subnet) {
#if 0 /* It's redundant log message */
                ogs_error("[DROP] Cannot find subnet V:%d, IPv4:%p, IPv6:%p",
                        ip_h->ip_v, sess->ipv4, sess->ipv6);
                ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
#endif
                goto cleanup;
            }

            dev = subnet->dev;
            ogs_assert(dev);

            /* Increment total & ul octets + pkts */
            for (i = 0; i < pdr->num_of_urr; i++)
                upf_sess_urr_acc_add(sess, pdr->urr[i], pkbuf->len, true);

            /*
             * If destined to another UE on the same subnet,
             * hairpin back out (when ue_to_ue_hairpin is enabled).
             *
             * When disabled, the packet falls through to the TUN interface
             * and is hairpinned by the Linux kernel or an upstream router.
             *
             * subnet is already resolved from the source UE
             * (sess->ipv4->subnet or sess->ipv6->subnet).
             * A cheap subnet check gates the session lookup so that
             * normal internet traffic does not touch the hash table.
             */
            if (upf_self()->ue_to_ue_hairpin) {
                if (ip_h->ip_v == 4 && subnet->family == AF_INET) {
                    if (ogs_unlikely(
                            (ip_h->ip_dst.s_addr & subnet->sub.mask[0]) ==
                            subnet->sub.sub[0]))
                        dst_sess = upf_sess_find_by_ipv4(ip_h->ip_dst.s_addr);
                } else if (ip_h->ip_v == 6 && subnet->family == AF_INET6) {
                    struct ip6_hdr *ip6_h = (struct ip6_hdr *)ip_h;
                    uint32_t *dst6 = (void *)ip6_h->ip6_dst.s6_addr;

                    if (ogs_unlikely(
                        (dst6[0] & subnet->sub.mask[0]) == subnet->sub.sub[0] &&
                        (dst6[1] & subnet->sub.mask[1]) == subnet->sub.sub[1] &&
                        (dst6[2] & subnet->sub.mask[2]) == subnet->sub.sub[2] &&
                        (dst6[3] & subnet->sub.mask[3]) == subnet->sub.sub[3]))
                        dst_sess = upf_sess_find_by_ipv6(dst6);
                }
            }

            if (ogs_unlikely(dst_sess != NULL) && dst_sess != sess) {
                memset(&dl_report, 0, sizeof(dl_report));

                ogs_list_for_each(&dst_sess->pfcp.pdr_list, dl_pdr) {
                    dl_far = dl_pdr->far;
                    ogs_assert(dl_far);

                    /* Check if PDR is Downlink */
                    if (dl_pdr->src_if != OGS_PFCP_INTERFACE_CORE)
                        continue;

                    /* Save the Fallback PDR : Lowest presedence downlink PDR */
                    dl_fallback_pdr = dl_pdr;

                    /* Check if FAR is Downlink */
                    if (dl_far->dst_if != OGS_PFCP_INTERFACE_ACCESS)
                        continue;

                    /* Check if Outer header creation */
                    if (dl_far->outer_header_creation.gtpu4 == 0 &&
                        dl_far->outer_header_creation.gtpu6 == 0)
                        continue;

                    /* Check if Rule List in PDR */
                    if (ogs_list_first(&dl_pdr->rule_list) &&
                        ogs_pfcp_pdr_rule_find_by_packet(
                            dl_pdr, pkbuf) == NULL)
                        continue;

                    break;
                }

                if (!dl_pdr)
                    dl_pdr = dl_fallback_pdr;

                if (dl_pdr) {
                    /* Increment dl octets + pkts */
                    for (i = 0; i < dl_pdr->num_of_urr; i++)
                        upf_sess_urr_acc_add(
                            dst_sess, dl_pdr->urr[i],
                            pkbuf->len, false);

                    ogs_assert(true == ogs_pfcp_up_handle_pdr(
                        dl_pdr, OGS_GTPU_MSGTYPE_GPDU,
                        0, NULL, pkbuf, &dl_report));

                    if (dl_report.type.downlink_data_report) {
                        upf_sess_t *dl_sess = NULL;

                        ogs_assert(dl_pdr->sess);
                        dl_sess = UPF_SESS(dl_pdr->sess);
                        ogs_assert(dl_sess);

                        dl_report.downlink_data.pdr_id = dl_pdr->id;
                        if (dl_pdr->qer && dl_pdr->qer->qfi)
                            dl_report.downlink_data.qfi =
                                dl_pdr->qer->qfi; /* for 5GC */

                        ogs_assert(OGS_OK ==
                            upf_pfcp_send_session_report_request(dl_sess, &dl_report));
                    }

                    /*
                    * The ogs_pfcp_up_handle_pdr() function
                    * buffers or frees the Packet Buffer(pkbuf) memory.
                    */
                    return;
                }
                /* No matching downlink PDR - fall through to TUN */
            }

            /*
             * TAP mode: intercept Neighbor Solicitations from the UE that
             * are trying to resolve the gateway link-local address (fe80::1)
             * advertised in our synthetic Router Advertisement.
             *
             * If gw6_mac_addr is known, reply with a synthetic NA so only the
             * requesting UE gets the answer.  If it is not yet known, drop the
             * NS rather than forwarding it to the real router — forwarding
             * would cause the router to send a unicast NA to the UE's fe80::
             * address, which would be dropped by the downlink link-local filter
             * anyway.  The UE will retry the NS once gw6_mac_addr is learned.
             */
            if (dev && dev->is_tap && ip_h->ip_v == 6 &&
                    pkbuf->len >= (int)(sizeof(struct ip6_hdr) +
                                       sizeof(struct nd_neighbor_solicit))) {
                struct ip6_hdr *ip6_ns =
                    (struct ip6_hdr *)pkbuf->data;
                if (ip6_ns->ip6_nxt == IPPROTO_ICMPV6) {
                    struct nd_neighbor_solicit *ns_h =
                        (struct nd_neighbor_solicit *)
                        (pkbuf->data + sizeof(struct ip6_hdr));
                    if (ns_h->nd_ns_type == ND_NEIGHBOR_SOLICIT) {
                        /*
                         * Check target = fe80::1.
                         * The address is stored big-endian in s6_addr[].
                         * fe80::1 = { 0xfe,0x80, 14×0x00, 0x01 }.
                         */
                        static const uint8_t gw_ll_target[16] = {
                            0xfe,0x80, 0,0, 0,0, 0,0,
                            0,0, 0,0, 0,0, 0,0x01
                        };
                        if (memcmp(ns_h->nd_ns_target.s6_addr,
                                   gw_ll_target, 16) == 0) {
                            static const uint8_t zero_mac6[ETHER_ADDR_LEN] = {0};
                            if (memcmp(dev->gw6_mac_addr,
                                       zero_mac6, ETHER_ADDR_LEN) != 0) {
                                _send_gateway_neighbor_advertisement(
                                        sess,
                                        ip6_ns->ip6_src.s6_addr,
                                        dev);
                            }
                            /* Drop whether or not we replied — never forward
                             * to the real router. */
                            goto cleanup;
                        }
                    }
                }
            }

            if (dev->is_tap) {
                /*
                 * UE uplink frames forwarded to the gateway via TAP:
                 *   src MAC = subscriber's IMSI-derived MAC (proxy fallback if
                 *             no IMSI), so the gateway can identify the source
                 *             subscriber at L2 and update its ARP/NDP cache.
                 *   dst MAC = gateway MAC learned from incoming TAP frames
                 *             (broadcast until the first frame is received).
                 */
                static const uint8_t broadcast_mac[ETHER_ADDR_LEN] =
                    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
                static const uint8_t zero_mac[ETHER_ADDR_LEN] = {0};
                const uint8_t *src_mac =
                    (memcmp(sess->imeisv_mac_addr, zero_mac,
                            ETHER_ADDR_LEN) != 0) ?
                    sess->imeisv_mac_addr : proxy_mac_addr;
                /*
                 * Select the Ethernet destination MAC:
                 *
                 * For IPv6 multicast destinations (e.g. RS to ff02::2,
                 * NS to ff02::1:ffXX:XXXX) the Ethernet dst is the
                 * derived multicast MAC 33:33:<last-4-bytes> per RFC 2464.
                 * Using the gateway unicast MAC for these frames is
                 * non-standard and breaks on shared Ethernet segments.
                 *
                 * For unicast IPv6 and all IPv4, use the learned gateway
                 * MAC; fall back to broadcast until the MAC is known.
                 */
                uint8_t mcast_mac[ETHER_ADDR_LEN];
                const uint8_t *dst_mac;
                if (eth_type == ETHERTYPE_IPV6 &&
                        pkbuf->len >= (int)sizeof(struct ip6_hdr)) {
                    struct ip6_hdr *ip6up = (struct ip6_hdr *)pkbuf->data;
                    if (IN6_IS_ADDR_MULTICAST(&ip6up->ip6_dst)) {
                        mcast_mac[0] = 0x33;
                        mcast_mac[1] = 0x33;
                        mcast_mac[2] = ip6up->ip6_dst.s6_addr[12];
                        mcast_mac[3] = ip6up->ip6_dst.s6_addr[13];
                        mcast_mac[4] = ip6up->ip6_dst.s6_addr[14];
                        mcast_mac[5] = ip6up->ip6_dst.s6_addr[15];
                        dst_mac = mcast_mac;
                    } else {
                        const uint8_t *gw_mac = dev->gw6_mac_addr;
                        dst_mac = (memcmp(gw_mac, zero_mac,
                                          ETHER_ADDR_LEN) != 0) ?
                                  gw_mac : broadcast_mac;
                    }
                } else {
                    const uint8_t *gw_mac = dev->gw_mac_addr;
                    dst_mac = (memcmp(gw_mac, zero_mac,
                                      ETHER_ADDR_LEN) != 0) ?
                              gw_mac : broadcast_mac;
                }
                if (!eth_type) {
                    ogs_error("[DROP] eth_type is 0 on TAP uplink path");
                    goto cleanup;
                }
                eth_type = htobe16(eth_type);
                ogs_pkbuf_push(pkbuf, sizeof(eth_type));
                memcpy(pkbuf->data, &eth_type, sizeof(eth_type));
                ogs_pkbuf_push(pkbuf, ETHER_ADDR_LEN);
                memcpy(pkbuf->data, src_mac, ETHER_ADDR_LEN);
                ogs_pkbuf_push(pkbuf, ETHER_ADDR_LEN);
                memcpy(pkbuf->data, dst_mac, ETHER_ADDR_LEN);
            }

            if (ogs_tun_write(dev->fd, pkbuf) != OGS_OK)
                ogs_warn("ogs_tun_write() failed");

        } else {

            /*
             * The following code is unnecessary and has been removed.
             * The reason for its initial implementation is unclear.
             */
#if 0 /* <DEPRECATED> */
            if (far->dst_if == OGS_PFCP_INTERFACE_CP_FUNCTION) {
                if (!far->gnode) {
                    ogs_error("No Outer Header Creation in FAR");
                    goto cleanup;
                }

                if ((far->apply_action & OGS_PFCP_APPLY_ACTION_FORW) == 0) {
                    ogs_error("Not supported Apply Action [0x%x]",
                                far->apply_action);
                    goto cleanup;
                }
            }
#endif

            ogs_assert(true == ogs_pfcp_up_handle_pdr(
                        pdr, header_desc.type, len, &header_desc,
                        pkbuf, &report));

#if 0 /* <DEPRECATED> */
            if (far->dst_if == OGS_PFCP_INTERFACE_CP_FUNCTION) {
                ogs_assert(report.type.downlink_data_report == 0);
            }
#endif

            if (report.type.downlink_data_report) {
                ogs_error("User Traffic Buffered");

                report.downlink_data.pdr_id = pdr->id;
                if (pdr->qer && pdr->qer->qfi)
                    report.downlink_data.qfi = pdr->qer->qfi; /* for 5GC */

                ogs_assert(OGS_OK ==
                    upf_pfcp_send_session_report_request(sess, &report));
            }

            /*
             * The ogs_pfcp_up_handle_pdr() function
             * buffers or frees the Packet Buffer(pkbuf) memory.
             */
            return;
        }
    } else {
        ogs_error("[DROP] Invalid GTPU Type [%d]", header_desc.type);
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
    }

cleanup:
    ogs_pkbuf_free(pkbuf);
}

int upf_gtp_init(void)
{
    ogs_pkbuf_config_t config;
    memset(&config, 0, sizeof config);

    config.cluster_2048_pool = ogs_app()->pool.gtpu;

#if OGS_USE_TALLOC == 1
    /* allocate a talloc pool for GTP to ensure it doesn't have to go back
     * to the libc malloc all the time */
    packet_pool = talloc_pool(__ogs_talloc_core, 1000*1024);
    ogs_assert(packet_pool);
#else
    packet_pool = ogs_pkbuf_pool_create(&config);
#endif

    return OGS_OK;
}

void upf_gtp_final(void)
{
    ogs_pkbuf_pool_destroy(packet_pool);
}

static void _get_dev_mac_addr(char *ifname, uint8_t *mac_addr)
{
#ifdef SIOCGIFHWADDR
    int fd = socket(PF_INET, SOCK_DGRAM, 0);
    ogs_assert(fd);
    struct ifreq req;
    memset(&req, 0, sizeof(req));
    ogs_cpystrn(req.ifr_name, ifname, IF_NAMESIZE-1);
    ogs_assert(ioctl(fd, SIOCGIFHWADDR, &req) == 0);
    memcpy(mac_addr, req.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
#else
    struct ifaddrs *ifap;
    ogs_assert(getifaddrs(&ifap) == 0);
    struct ifaddrs *p;
    for (p = ifap; p; p = p->ifa_next) {
        if (strncmp(ifname, p->ifa_name, IF_NAMESIZE-1) == 0) {
            struct sockaddr_dl* sdp = (struct sockaddr_dl*) p->ifa_addr;
            memcpy(mac_addr, sdp->sdl_data + sdp->sdl_nlen, ETHER_ADDR_LEN);
            freeifaddrs(ifap);
            return;
        }
    }
    ogs_assert(0); /* interface not found. */
#endif
}

#define GW_ARP_RETRY_INTERVAL   (2 * OGS_USEC_PER_SEC)
#define GW_ARP_REFRESH_INTERVAL (60 * OGS_USEC_PER_SEC)

static void _send_gw_arp_request(ogs_pfcp_dev_t *dev)
{
    ogs_pfcp_subnet_t *subnet = NULL;
    ogs_pkbuf_t *pkbuf = NULL;
    uint8_t size;

    ogs_list_for_each(&ogs_pfcp_self()->subnet_list, subnet) {
        if (subnet->dev != dev || subnet->family != AF_INET)
            continue;
        if (!subnet->gw.family)
            continue;

        /*
         * Prefer sending the ARP who-has with a real sender IP/MAC taken from
         * any active session on this subnet.  A probe with sender_ip=0.0.0.0
         * (RFC 5227) is often silently ignored by gateways.  Using a real UE
         * IP guarantees a unicast reply that updates gw_mac_addr, which is
         * important for detecting gateway MAC changes (e.g. router failover)
         * even when no downlink traffic is flowing.
         * Fall back to the RFC 5227 probe when no sessions are active.
         */
        {
            static const uint8_t zero_mac[ETHER_ADDR_LEN] = {0};
            upf_sess_t *s = NULL;
            const uint8_t *sender_ip = NULL;
            const uint8_t *sender_mac = proxy_mac_addr;

            ogs_list_for_each(&upf_self()->sess_list, s) {
                if (!s->ipv4)
                    continue;
                if (s->ipv4->subnet != subnet)
                    continue;
                sender_ip = (const uint8_t *)s->ipv4->addr;
                if (memcmp(s->imeisv_mac_addr, zero_mac, ETHER_ADDR_LEN) != 0)
                    sender_mac = s->imeisv_mac_addr;
                break;
            }

            pkbuf = ogs_pkbuf_alloc(packet_pool, OGS_MAX_PKT_LEN);
            ogs_assert(pkbuf);
            ogs_pkbuf_reserve(pkbuf, OGS_TUN_MAX_HEADROOM);
            ogs_pkbuf_put(pkbuf, OGS_MAX_PKT_LEN - OGS_TUN_MAX_HEADROOM);

            if (sender_ip) {
                size = arp_who_has_build(pkbuf->data,
                        (const uint8_t *)subnet->gw.sub,
                        sender_ip, sender_mac);
            } else {
                size = arp_request_build(pkbuf->data,
                        (const uint8_t *)subnet->gw.sub, proxy_mac_addr);
            }

            if (size > 0) {
                char buf[OGS_ADDRSTRLEN];
                ogs_pkbuf_trim(pkbuf, size);
                if (ogs_tun_write(dev->fd, pkbuf) != OGS_OK)
                    ogs_warn("[%s] gateway ARP request write failed", dev->ifname);
                else
                    ogs_debug("[%s] ARP request sent for gateway [%s]",
                        dev->ifname,
                        OGS_INET_NTOP(&subnet->gw.sub, buf));
            }
            ogs_pkbuf_free(pkbuf);
        }
        break; /* One subnet per device is sufficient to learn the gateway MAC */
    }
}

static void _gw_arp_retry_cb(void *data)
{
    static const uint8_t zero_mac[ETHER_ADDR_LEN] = {0};
    ogs_pfcp_dev_t *dev = (ogs_pfcp_dev_t *)data;
    bool learned;

    ogs_assert(dev);

    _send_gw_arp_request(dev);

    /* Retry at a fast rate until the gateway MAC is first learned, then
     * keep refreshing once per minute so that a gateway MAC change
     * (e.g. router replacement or failover) is picked up promptly. */
    learned = (memcmp(dev->gw_mac_addr, zero_mac, ETHER_ADDR_LEN) != 0);
    ogs_timer_start(dev->t_gw_arp,
            learned ? GW_ARP_REFRESH_INTERVAL : GW_ARP_RETRY_INTERVAL);
}

static void _send_gw_nd_request(ogs_pfcp_dev_t *dev)
{
    ogs_pfcp_subnet_t *subnet = NULL;
    ogs_pkbuf_t *pkbuf = NULL;
    uint8_t size;

    ogs_list_for_each(&ogs_pfcp_self()->subnet_list, subnet) {
        if (subnet->dev != dev || subnet->family != AF_INET6)
            continue;
        if (!subnet->gw.family)
            continue;

        /*
         * Search for an active IPv6 session on this subnet and use its MAC.
         * Sending NS from a real UE MAC is more likely to elicit a gateway
         * response than using the proxy MAC, and helps detect gateway MAC
         * changes (e.g. router failover) even when no downlink traffic flows.
         * Falls back to proxy_mac_addr when no sessions are active.
         */
        {
            static const uint8_t zero_mac[ETHER_ADDR_LEN] = {0};
            upf_sess_t *s = NULL;
            const uint8_t *sender_mac = proxy_mac_addr;

            ogs_list_for_each(&upf_self()->sess_list, s) {
                if (!s->ipv6)
                    continue;
                if (s->ipv6->subnet != subnet)
                    continue;
                if (memcmp(s->imeisv_mac_addr, zero_mac, ETHER_ADDR_LEN) != 0)
                    sender_mac = s->imeisv_mac_addr;
                break;
            }

            pkbuf = ogs_pkbuf_alloc(packet_pool, OGS_MAX_PKT_LEN);
            ogs_assert(pkbuf);
            ogs_pkbuf_reserve(pkbuf, OGS_TUN_MAX_HEADROOM);
            ogs_pkbuf_put(pkbuf, OGS_MAX_PKT_LEN - OGS_TUN_MAX_HEADROOM);
            size = ns_request_build(pkbuf->data,
                    (const uint8_t *)subnet->gw.sub, sender_mac);

            if (size > 0) {
                char buf[OGS_ADDRSTRLEN];
                ogs_pkbuf_trim(pkbuf, size);
                if (ogs_tun_write(dev->fd, pkbuf) != OGS_OK)
                    ogs_warn("[%s] gateway NS write failed", dev->ifname);
                else
                    ogs_debug("[%s] NS sent for IPv6 gateway [%s]",
                        dev->ifname,
                        OGS_INET6_NTOP(&subnet->gw.sub, buf));
            }
            ogs_pkbuf_free(pkbuf);
        }
        break; /* One IPv6 subnet per device is sufficient */
    }
}

static void _gw_nd_retry_cb(void *data)
{
    static const uint8_t zero_mac[ETHER_ADDR_LEN] = {0};
    ogs_pfcp_dev_t *dev = (ogs_pfcp_dev_t *)data;
    bool learned;

    ogs_assert(dev);

    _send_gw_nd_request(dev);

    learned = (memcmp(dev->gw6_mac_addr, zero_mac, ETHER_ADDR_LEN) != 0);
    ogs_timer_start(dev->t_gw_nd,
            learned ? GW_ARP_REFRESH_INTERVAL : GW_ARP_RETRY_INTERVAL);
}

int upf_gtp_open(void)
{
    ogs_pfcp_dev_t *dev = NULL;
    ogs_pfcp_subnet_t *subnet = NULL;
    ogs_socknode_t *node = NULL;
    ogs_sock_t *sock = NULL;
    int rc;

    ogs_list_for_each(&ogs_gtp_self()->gtpu_list, node) {
        sock = ogs_gtp_server(node);
        if (!sock) return OGS_ERROR;

        if (sock->family == AF_INET)
            ogs_gtp_self()->gtpu_sock = sock;
        else if (sock->family == AF_INET6)
            ogs_gtp_self()->gtpu_sock6 = sock;

        node->poll = ogs_pollset_add(ogs_app()->pollset,
                OGS_POLLIN, sock->fd, _gtpv1_u_recv_cb, sock);
        ogs_assert(node->poll);
    }

    OGS_SETUP_GTPU_SERVER;

    /* NOTE : tun device can be created via following command.
     *
     * $ sudo ip tuntap add name ogstun mode tun
     *
     * Also, before running upf, assign the one IP from IP pool of UE
     * to ogstun. The IP should not be assigned to UE
     *
     * $ sudo ifconfig ogstun 45.45.0.1/16 up
     *
     */

    /* Open Tun interface */
    ogs_list_for_each(&ogs_pfcp_self()->dev_list, dev) {
        dev->is_tap = strstr(dev->ifname, "tap");
        dev->fd = ogs_tun_open(dev->ifname, OGS_MAX_IFNAME_LEN, dev->is_tap);
        if (dev->fd == INVALID_SOCKET) {
            ogs_error("tun_open(dev:%s) failed", dev->ifname);
            return OGS_ERROR;
        }

        if (dev->is_tap) {
            _get_dev_mac_addr(dev->ifname, dev->mac_addr);
            dev->poll = ogs_pollset_add(ogs_app()->pollset,
                    OGS_POLLIN, dev->fd, _gtpv1_tun_recv_eth_cb, NULL);
            ogs_assert(dev->poll);

            /* Send an initial ARP request for the IPv4 gateway and retry
             * every GW_ARP_RETRY_INTERVAL until the MAC is learned. */
            dev->t_gw_arp = ogs_timer_add(
                    ogs_app()->timer_mgr, _gw_arp_retry_cb, dev);
            ogs_assert(dev->t_gw_arp);
            _send_gw_arp_request(dev);
            ogs_timer_start(dev->t_gw_arp, GW_ARP_RETRY_INTERVAL);

            /* Send an initial NS for the IPv6 gateway (may differ from the
             * IPv4 gateway) and retry until the MAC is learned. */
            dev->t_gw_nd = ogs_timer_add(
                    ogs_app()->timer_mgr, _gw_nd_retry_cb, dev);
            ogs_assert(dev->t_gw_nd);
            _send_gw_nd_request(dev);
            ogs_timer_start(dev->t_gw_nd, GW_ARP_RETRY_INTERVAL);
        } else {
            dev->poll = ogs_pollset_add(ogs_app()->pollset,
                    OGS_POLLIN, dev->fd, _gtpv1_tun_recv_cb, NULL);
            ogs_assert(dev->poll);
        }

        ogs_assert(dev->poll);
    }

    /*
     * On Linux, it is possible to create a persistent tun/tap
     * interface which will continue to exist even if open5gs quit,
     * although this is normally not required.
     * It can be useful to set up a tun/tap interface owned
     * by a non-root user, so open5gs can be started without
     * needing any root privileges at all.
     */

    /* Set P-to-P IP address with Netmask
     * Note that Linux will skip this configuration */
    ogs_list_for_each(&ogs_pfcp_self()->subnet_list, subnet) {
        ogs_assert(subnet->dev);
        rc = ogs_tun_set_ip(subnet->dev->ifname, &subnet->gw, &subnet->sub);
        if (rc != OGS_OK) {
            ogs_error("ogs_tun_set_ip(dev:%s) failed", subnet->dev->ifname);
            return OGS_ERROR;
        }
    }

    return OGS_OK;
}

void upf_gtp_close(void)
{
    ogs_pfcp_dev_t *dev = NULL;

    ogs_socknode_remove_all(&ogs_gtp_self()->gtpu_list);

    ogs_list_for_each(&ogs_pfcp_self()->dev_list, dev) {
        if (dev->t_gw_arp)
            ogs_timer_delete(dev->t_gw_arp);
        if (dev->t_gw_nd)
            ogs_timer_delete(dev->t_gw_nd);
        if (dev->poll)
            ogs_pollset_remove(dev->poll);
        ogs_closesocket(dev->fd);
    }
}

static void upf_gtp_handle_multicast(ogs_pkbuf_t *recvbuf)
{
    struct ip *ip_h =  NULL;
    struct ip6_hdr *ip6_h = NULL;
    ogs_pfcp_user_plane_report_t report;

    ip_h = (struct ip *)recvbuf->data;
    if (ip_h->ip_v == 6) {
#if COMPILE_ERROR_IN_MAC_OS_X  /* Compiler error in Mac OS X platform */
        ip6_h = (struct ip6_hdr *)recvbuf->data;
        if (IN6_IS_ADDR_MULTICAST(&ip6_h->ip6_dst))
#else
        struct in6_addr ip6_dst;
        ip6_h = (struct ip6_hdr *)recvbuf->data;
        memcpy(&ip6_dst, &ip6_h->ip6_dst, sizeof(struct in6_addr));
        if (IN6_IS_ADDR_MULTICAST(&ip6_dst))
#endif
        {
            upf_sess_t *sess = NULL;

            /* IPv6 Multicast */
            ogs_list_for_each(&upf_self()->sess_list, sess) {
                if (sess->ipv6) {
                    /* PDN IPv6 is available */
                    ogs_pfcp_pdr_t *pdr = NULL;

                    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
                        if (pdr->src_if == OGS_PFCP_INTERFACE_CORE) {
                            ogs_pkbuf_t *sendbuf = ogs_pkbuf_copy(recvbuf);
                            ogs_assert(sendbuf);
                            ogs_assert(true ==
                                ogs_pfcp_up_handle_pdr(
                                    pdr, OGS_GTPU_MSGTYPE_GPDU, 0,
                                    NULL, sendbuf, &report));
                            break;
                        }
                    }

                    return;
                }
            }
        }
    }
}

/*
 * Deliver an IPv6 multicast packet received from the TAP (e.g. a Router
 * Advertisement to ff02::1) to every IPv6 UE session homed on that TAP device.
 *
 * upf_sess_find_by_ue_ip_address() cannot be used for these packets because
 * it looks up sessions by their global /64 prefix, and multicast or link-local
 * destination addresses never match.
 */
static void upf_gtp_handle_tap_ipv6_mcast(
        ogs_pkbuf_t *recvbuf, ogs_pfcp_dev_t *tap_dev)
{
    upf_sess_t *sess = NULL;
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_user_plane_report_t report;

    ogs_list_for_each(&upf_self()->sess_list, sess) {
        if (!sess->ipv6) continue;
        if (!sess->ipv6->subnet) continue;
        if (sess->ipv6->subnet->dev != tap_dev) continue;

        ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
            if (pdr->src_if == OGS_PFCP_INTERFACE_CORE) {
                ogs_pkbuf_t *sendbuf = ogs_pkbuf_copy(recvbuf);
                if (!sendbuf) continue;
                ogs_assert(true == ogs_pfcp_up_handle_pdr(
                    pdr, OGS_GTPU_MSGTYPE_GPDU, 0,
                    NULL, sendbuf, &report));
                break;
            }
        }
    }
}
