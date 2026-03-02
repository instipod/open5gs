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

#ifndef SMF_DHCP_CLIENT_H
#define SMF_DHCP_CLIENT_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Look up the per-DNN DHCP configuration for the given DNN name.
 * Returns NULL if no DHCP entry is configured for that DNN.
 */
smf_dhcp_config_t *smf_dhcp_find_config_by_dnn(const char *dnn);

/*
 * Perform a DHCP DISCOVER → OFFER → REQUEST → ACK exchange with the
 * server specified in cfg.  A dummy MAC address is derived from the
 * UE's IMSI BCD string: bytes 0-2 come from cfg->mac_prefix and bytes
 * 3-5 are the lower 24 bits of the last-9-digits of the IMSI.
 *
 * On success returns OGS_OK and writes the offered IPv4 address
 * (network byte order) into *out_ipv4_be.
 * On failure (timeout, NAK, socket error) returns OGS_ERROR.
 */
int smf_dhcp_acquire(smf_sess_t *sess, smf_dhcp_config_t *cfg,
        uint32_t *out_ipv4_be);

/*
 * Send a DHCP RELEASE for the IPv4 address currently held by sess->ipv4.
 * The same dummy MAC used during acquire is regenerated from the IMSI.
 * No response is expected (RFC 2131 §4.4.4).
 */
void smf_dhcp_release(smf_sess_t *sess);

#ifdef __cplusplus
}
#endif

#endif /* SMF_DHCP_CLIENT_H */
