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

#include "mme-context.h"
#include "mme-webhook.h"

#include "sbi/openapi/external/cJSON.h"
#include <time.h>

static void add_timestamp(cJSON *root)
{
    char timestamp[64];
    time_t now;
    struct tm *tm_info;

    time(&now);
    tm_info = gmtime(&now);
    if (tm_info) {
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm_info);
        cJSON_AddStringToObject(root, "timestamp", timestamp);
    }
}

static void add_plmn_id(cJSON *parent, const char *key, ogs_plmn_id_t *plmn_id)
{
    char plmn_str[OGS_PLMNIDSTRLEN] = {0};

    ogs_assert(parent);
    ogs_assert(plmn_id);

    ogs_plmn_id_to_string(plmn_id, plmn_str);
    cJSON_AddStringToObject(parent, key, plmn_str);
}

void mme_webhook_send_enb_attached(mme_enb_t *enb)
{
    mme_context_t *mme_ctx = NULL;
    cJSON *root = NULL;
    cJSON *ta_list = NULL;
    char *payload = NULL;
    char buf[OGS_ADDRSTRLEN];
    char label[64];
    int i;

    ogs_assert(enb);
    mme_ctx = mme_self();
    ogs_assert(mme_ctx);

    if (!mme_ctx->webhook.enabled || !mme_ctx->webhook.url)
        return;

    root = cJSON_CreateObject();
    if (!root) return;

    cJSON_AddStringToObject(root, "event", "enb_attached");
    add_timestamp(root);
    cJSON_AddNumberToObject(root, "enb_id", enb->enb_id);
    add_plmn_id(root, "plmn_id", &enb->plmn_id);

    if (enb->sctp.addr) {
        cJSON_AddStringToObject(root, "sctp_addr",
                OGS_ADDR(enb->sctp.addr, buf));
    }

    ta_list = cJSON_AddArrayToObject(root, "supported_ta_list");
    if (ta_list) {
        for (i = 0; i < enb->num_of_supported_ta_list; i++) {
            cJSON *ta = cJSON_CreateObject();
            if (ta) {
                cJSON_AddNumberToObject(ta, "tac",
                        enb->supported_ta_list[i].tac);
                add_plmn_id(ta, "plmn_id",
                        &enb->supported_ta_list[i].plmn_id);
                cJSON_AddItemToArray(ta_list, ta);
            }
        }
    }

    payload = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (payload) {
        snprintf(label, sizeof(label), "enb_attached:%d", enb->enb_id);
        ogs_webhook_send(&mme_ctx->webhook, payload, label);
        cJSON_free(payload);
    }
}

void mme_webhook_send_enb_detached(mme_enb_t *enb)
{
    mme_context_t *mme_ctx = NULL;
    cJSON *root = NULL;
    char *payload = NULL;
    char buf[OGS_ADDRSTRLEN];
    char label[64];

    ogs_assert(enb);
    mme_ctx = mme_self();
    ogs_assert(mme_ctx);

    if (!mme_ctx->webhook.enabled || !mme_ctx->webhook.url)
        return;

    root = cJSON_CreateObject();
    if (!root) return;

    cJSON_AddStringToObject(root, "event", "enb_detached");
    add_timestamp(root);
    cJSON_AddNumberToObject(root, "enb_id", enb->enb_id);
    add_plmn_id(root, "plmn_id", &enb->plmn_id);

    if (enb->sctp.addr) {
        cJSON_AddStringToObject(root, "sctp_addr",
                OGS_ADDR(enb->sctp.addr, buf));
    }

    payload = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (payload) {
        snprintf(label, sizeof(label), "enb_detached:%d", enb->enb_id);
        ogs_webhook_send(&mme_ctx->webhook, payload, label);
        cJSON_free(payload);
    }
}

void mme_webhook_send_ue_attached(mme_ue_t *mme_ue)
{
    mme_context_t *mme_ctx = NULL;
    enb_ue_t *enb_ue = NULL;
    mme_enb_t *enb = NULL;
    cJSON *root = NULL;
    cJSON *tai = NULL;
    char *payload = NULL;

    ogs_assert(mme_ue);
    mme_ctx = mme_self();
    ogs_assert(mme_ctx);

    if (!mme_ctx->webhook.enabled || !mme_ctx->webhook.url)
        return;

    root = cJSON_CreateObject();
    if (!root) return;

    cJSON_AddStringToObject(root, "event", "ue_attached");
    add_timestamp(root);

    if (MME_UE_HAVE_IMSI(mme_ue))
        cJSON_AddStringToObject(root, "imsi", mme_ue->imsi_bcd);

    /* Add eNB ID if we can find it */
    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    if (enb_ue) {
        enb = mme_enb_find_by_id(enb_ue->enb_id);
        if (enb)
            cJSON_AddNumberToObject(root, "enb_id", enb->enb_id);
    }

    /* Add TAI */
    tai = cJSON_CreateObject();
    if (tai) {
        add_plmn_id(tai, "plmn_id", &mme_ue->tai.plmn_id);
        cJSON_AddNumberToObject(tai, "tac", mme_ue->tai.tac);
        cJSON_AddItemToObject(root, "tai", tai);
    }

    payload = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (payload) {
        ogs_webhook_send(&mme_ctx->webhook, payload, mme_ue->imsi_bcd);
        cJSON_free(payload);
    }
}

void mme_webhook_send_ue_detached(mme_ue_t *mme_ue)
{
    mme_context_t *mme_ctx = NULL;
    enb_ue_t *enb_ue = NULL;
    mme_enb_t *enb = NULL;
    cJSON *root = NULL;
    char *payload = NULL;
    const char *detach_type_str;

    ogs_assert(mme_ue);
    mme_ctx = mme_self();
    ogs_assert(mme_ctx);

    if (!mme_ctx->webhook.enabled || !mme_ctx->webhook.url)
        return;

    root = cJSON_CreateObject();
    if (!root) return;

    cJSON_AddStringToObject(root, "event", "ue_detached");
    add_timestamp(root);

    if (MME_UE_HAVE_IMSI(mme_ue))
        cJSON_AddStringToObject(root, "imsi", mme_ue->imsi_bcd);

    switch (mme_ue->detach_type) {
    case MME_DETACH_TYPE_REQUEST_FROM_UE:
        detach_type_str = "ue_initiated";
        break;
    case MME_DETACH_TYPE_MME_EXPLICIT:
        detach_type_str = "mme_explicit";
        break;
    case MME_DETACH_TYPE_HSS_EXPLICIT:
        detach_type_str = "hss_explicit";
        break;
    case MME_DETACH_TYPE_MME_IMPLICIT:
        detach_type_str = "mme_implicit";
        break;
    case MME_DETACH_TYPE_HSS_IMPLICIT:
        detach_type_str = "hss_implicit";
        break;
    default:
        detach_type_str = "unknown";
        break;
    }
    cJSON_AddStringToObject(root, "detach_type", detach_type_str);

    /* Add eNB ID if we can find it */
    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    if (enb_ue) {
        enb = mme_enb_find_by_id(enb_ue->enb_id);
        if (enb)
            cJSON_AddNumberToObject(root, "enb_id", enb->enb_id);
    }

    payload = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (payload) {
        ogs_webhook_send(&mme_ctx->webhook, payload, mme_ue->imsi_bcd);
        cJSON_free(payload);
    }
}
