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

#include <cstdint>

#include <tins/arp.h>
#include <tins/ethernetII.h>
#include <tins/hw_address.h>
#include <tins/icmpv6.h>
#include <tins/ipv6.h>
#include <tins/exceptions.h>

#include "arp-nd.h"

using namespace::Tins;


uint8_t _serialize_reply(uint8_t *reply_data, EthernetII &reply)
{
    PDU::serialization_type serialized = reply.serialize();
    memcpy(reply_data, serialized.data(), serialized.size());
    return serialized.size();
}

bool _parse_arp(EthernetII &pdu)
{
    if (pdu.payload_type() == ETHERTYPE_ARP) {
        const ARP& arp = pdu.rfind_pdu<ARP>();
        return arp.opcode() == ARP::REQUEST && pdu.dst_addr().is_broadcast();
    }
    return false;
}

bool is_arp_req(uint8_t *data, uint len)
{
    EthernetII pdu(data, len);
    return _parse_arp(pdu);
}

uint32_t arp_parse_target_addr(uint8_t *data, uint len)
{
    EthernetII pdu(data, len);
    if (pdu.payload_type() == ETHERTYPE_ARP) {
        const ARP& arp = pdu.rfind_pdu<ARP>();
        return arp.target_ip_addr();
    }
    return 0x0;
}

uint8_t arp_reply(uint8_t *reply_data, uint8_t *request_data, uint len,
        const uint8_t *mac)
{
    EthernetII pdu(request_data, len);
    if (_parse_arp(pdu)) {
        HWAddress<ETHER_ADDR_LEN> source_mac(mac);
        const ARP& arp = pdu.rfind_pdu<ARP>();
        EthernetII reply = ARP::make_arp_reply(
            arp.sender_ip_addr(),
            arp.target_ip_addr(),
            arp.sender_hw_addr(),
            source_mac);
        return _serialize_reply(reply_data, reply);
    }
    return 0;
}

bool _parse_nd(EthernetII &pdu)
{
    if (pdu.payload_type() == ETHERTYPE_IPV6) {
        try {
            const ICMPv6& icmp6 = pdu.rfind_pdu<ICMPv6>();
            return icmp6.type() == ICMPv6::NEIGHBOUR_SOLICIT;
        }
        catch (Tins::pdu_not_found& e) {
            /* If it is not an ICMPv6 message, it can not be a NEIGHBOUR_SOLICIT */
            return false;
        }
    }
    return false;
}

bool is_nd_req(uint8_t *data, uint len)
{
    if (len < MAX_ND_SIZE) {
        EthernetII pdu(data, len);
        return _parse_nd(pdu);
    }
    return false;
}

uint8_t arp_request_build(uint8_t *buf, const uint8_t *target_ipv4,
        const uint8_t *sender_mac)
{
    /*
     * Standard ARP WHO-HAS request.  sender_ip is 0.0.0.0 (ARP probe
     * per RFC 5227) since the UPF has no IP address on the TAP interface.
     * All compliant implementations will still reply with their MAC.
     */
    uint32_t addr_ne;
    memcpy(&addr_ne, target_ipv4, sizeof(addr_ne));
    HWAddress<ETHER_ADDR_LEN> src_mac(sender_mac);
    IPv4Address tip(addr_ne);

    ARP req;
    req.opcode(ARP::REQUEST);
    req.sender_hw_addr(src_mac);
    req.sender_ip_addr(IPv4Address("0.0.0.0"));
    req.target_hw_addr(HWAddress<ETHER_ADDR_LEN>());
    req.target_ip_addr(tip);

    EthernetII frame(HWAddress<ETHER_ADDR_LEN>("ff:ff:ff:ff:ff:ff"), src_mac);
    frame /= req;
    return _serialize_reply(buf, frame);
}

uint8_t ns_request_build(uint8_t *buf, const uint8_t *target_ipv6,
        const uint8_t *sender_mac)
{
    /*
     * Neighbor Solicitation to discover the gateway's link-layer address.
     * Destination is the solicited-node multicast for the target address.
     * Source IPv6 is the link-local derived from sender_mac via EUI-64.
     * RFC 4861 §4.3: hop limit = 255, source link-layer option included.
     */

    /* Solicited-node multicast: ff02::1:ff<last-3-bytes-of-target> */
    uint8_t sol_node[16] = {
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0xff,
        target_ipv6[13], target_ipv6[14], target_ipv6[15]
    };
    /* Ethernet dst: 33:33:ff:<last-3> */
    uint8_t eth_dst[ETHER_ADDR_LEN] = {
        0x33, 0x33, 0xff,
        target_ipv6[13], target_ipv6[14], target_ipv6[15]
    };
    /* Link-local source derived from sender_mac via EUI-64 */
    uint8_t src_ip[16] = {
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        (uint8_t)(sender_mac[0] ^ 0x02), sender_mac[1], sender_mac[2],
        0xff, 0xfe,
        sender_mac[3], sender_mac[4], sender_mac[5]
    };

    IPv6Address target_addr(target_ipv6);
    IPv6Address sol_node_addr(sol_node);
    IPv6Address src_addr(src_ip);

    ICMPv6 ns(ICMPv6::NEIGHBOUR_SOLICIT);
    ns.target_addr(target_addr);
    ns.source_link_layer_addr(HWAddress<ETHER_ADDR_LEN>(sender_mac));

    IPv6 ip6(sol_node_addr, src_addr);
    ip6.hop_limit(255);

    HWAddress<ETHER_ADDR_LEN> dst_mac_addr(eth_dst);
    HWAddress<ETHER_ADDR_LEN> src_mac_addr(sender_mac);
    EthernetII frame(dst_mac_addr, src_mac_addr);
    frame /= ip6 / ns;
    return _serialize_reply(buf, frame);
}

uint8_t arp_who_has_build(uint8_t *buf, const uint8_t *target_ipv4,
        const uint8_t *sender_ipv4, const uint8_t *sender_mac)
{
    /*
     * Standard ARP WHO-HAS with a real sender IP so the target will reply
     * with its MAC.  Used after session establishment to learn the gateway
     * MAC using the UE's assigned IP as the sender address.
     */
    uint32_t tip_ne, sip_ne;
    memcpy(&tip_ne, target_ipv4, sizeof(tip_ne));
    memcpy(&sip_ne, sender_ipv4, sizeof(sip_ne));
    HWAddress<ETHER_ADDR_LEN> src_mac(sender_mac);
    IPv4Address tip(tip_ne);
    IPv4Address sip(sip_ne);

    ARP req;
    req.opcode(ARP::REQUEST);
    req.sender_hw_addr(src_mac);
    req.sender_ip_addr(sip);
    req.target_hw_addr(HWAddress<ETHER_ADDR_LEN>());
    req.target_ip_addr(tip);

    EthernetII frame(HWAddress<ETHER_ADDR_LEN>("ff:ff:ff:ff:ff:ff"), src_mac);
    frame /= req;
    return _serialize_reply(buf, frame);
}

uint8_t garp_build(uint8_t *buf, const uint8_t *ipv4_addr, const uint8_t *mac)
{
    /* Gratuitous ARP: sender == target, Ethernet destination is broadcast */
    uint32_t addr_ne;
    memcpy(&addr_ne, ipv4_addr, sizeof(addr_ne));
    HWAddress<ETHER_ADDR_LEN> src_mac(mac);
    IPv4Address ip(addr_ne);

    ARP garp;
    garp.opcode(ARP::REQUEST);
    garp.sender_hw_addr(src_mac);
    garp.sender_ip_addr(ip);
    garp.target_hw_addr(HWAddress<ETHER_ADDR_LEN>());
    garp.target_ip_addr(ip);

    EthernetII frame(HWAddress<ETHER_ADDR_LEN>("ff:ff:ff:ff:ff:ff"), src_mac);
    frame /= garp;
    return _serialize_reply(buf, frame);
}

bool nd_parse_target_addr(uint8_t *data, uint len, uint8_t *target_addr)
{
    EthernetII pdu(data, len);
    if (_parse_nd(pdu)) {
        const ICMPv6& icmp6 = pdu.rfind_pdu<ICMPv6>();
        IPv6Address target = icmp6.target_addr();
        std::copy(target.begin(), target.end(), target_addr);
        return true;
    }
    return false;
}

uint8_t nd_reply(uint8_t *reply_data, uint8_t *request_data, uint len,
        const uint8_t *mac)
{
    EthernetII pdu(request_data, len);
    if (_parse_nd(pdu)) {
        HWAddress<ETHER_ADDR_LEN> source_mac(mac);
        const ICMPv6& icmp6 = pdu.rfind_pdu<ICMPv6>();
        const IPv6& ip6_req = pdu.rfind_pdu<IPv6>();

        IPv6Address target = icmp6.target_addr();
        IPv6Address requester_ip = ip6_req.src_addr();

        ICMPv6 na(ICMPv6::NEIGHBOUR_ADVERT);
        na.target_link_layer_addr(source_mac);
        na.target_addr(target);
        na.solicited(true);
        na.override(true);

        /* IPv6(dst, src): reply goes back to the NS sender */
        IPv6 ip6_reply(requester_ip, target);
        ip6_reply.hop_limit(255);

        /* EthernetII(dst, src): unicast back to requester, source is the
         * MAC being advertised (not the multicast dst of the incoming NS) */
        EthernetII reply(pdu.src_addr(), source_mac);
        reply /= ip6_reply / na;
        return _serialize_reply(reply_data, reply);
    }
    return 0;
}
