/*
 * Copyright (C) 2025 by Open5GS Contributors
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

/*
 * GET /ue-disconnect?imsi=<IMSI>
 *
 * Force-disconnects the LTE UE with the given IMSI by initiating an
 * MME-implicit detach: all GTP sessions are deleted and an S1AP
 * UEContextReleaseCommand is sent to the eNB.
 *
 * curl -s "http://127.0.0.2:9090/ue-disconnect?imsi=460001234567890" | jq .
 */

#include <stdio.h>
#include <string.h>

#include "ogs-core.h"

#include "mme-context.h"
#include "mme-path.h"
#include "ue-disconnect.h"
#include "metrics/ogs-metrics.h"

size_t mme_ue_disconnect_action(void *conn, char *buf, size_t buflen)
{
    if (!buf || buflen == 0)
        return 0;

    const char *imsi = ogs_metrics_get_query_param(conn, "imsi");
    if (!imsi || !*imsi) {
        return (size_t)snprintf(buf, buflen,
                "{\"status\":\"error\","
                "\"message\":\"missing imsi parameter\"}");
    }

    mme_ue_t *mme_ue = mme_ue_find_by_imsi_bcd(imsi);
    if (!mme_ue) {
        return (size_t)snprintf(buf, buflen,
                "{\"status\":\"error\","
                "\"imsi\":\"%s\","
                "\"message\":\"UE not found\"}",
                imsi);
    }

    if (!ECM_CONNECTED(mme_ue)) {
        return (size_t)snprintf(buf, buflen,
                "{\"status\":\"error\","
                "\"imsi\":\"%s\","
                "\"message\":\"UE not connected\"}",
                imsi);
    }

    enb_ue_t *enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);

    mme_ue->detach_type = MME_DETACH_TYPE_MME_IMPLICIT;
    mme_send_delete_session_or_detach(enb_ue, mme_ue);

    return (size_t)snprintf(buf, buflen,
            "{\"status\":\"ok\","
            "\"imsi\":\"%s\","
            "\"message\":\"UE disconnect initiated\"}",
            imsi);
}
