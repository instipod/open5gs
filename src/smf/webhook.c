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

#include "context.h"
#include "webhook.h"

#include <curl/curl.h>
#include <time.h>

/* Callback for webhook response data - we just discard it */
static size_t webhook_write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    return size * nmemb;
}

/* Build JSON payload for webhook notification */
static char *build_webhook_payload(smf_sess_t *sess)
{
    smf_ue_t *smf_ue = NULL;
    cJSON *root = NULL;
    cJSON *assigned_ips = NULL;
    cJSON *snssai = NULL;
    char *payload_str = NULL;
    char ipv4_str[OGS_ADDRSTRLEN];
    char ipv6_str[OGS_ADDRSTRLEN];
    char timestamp[64];
    time_t now;
    struct tm *tm_info;

    ogs_assert(sess);
    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);

    if (!smf_ue) {
        ogs_error("Cannot find SMF UE for webhook payload");
        return NULL;
    }

    /* Create JSON root object */
    root = cJSON_CreateObject();
    if (!root) {
        ogs_error("Failed to create JSON object for webhook");
        return NULL;
    }

    /* Add event type */
    cJSON_AddStringToObject(root, "event", "ue_ip_assigned");

    /* Add timestamp (ISO 8601 format) */
    time(&now);
    tm_info = gmtime(&now);
    if (tm_info) {
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm_info);
        cJSON_AddStringToObject(root, "timestamp", timestamp);
    }

    /* Add SUPI (if available) */
    if (smf_ue->supi) {
        cJSON_AddStringToObject(root, "supi", smf_ue->supi);
    }

    /* Add IMSI */
    if (smf_ue->imsi_bcd && smf_ue->imsi_bcd[0]) {
        cJSON_AddStringToObject(root, "imsi", smf_ue->imsi_bcd);
    }

    /* Add DNN/APN */
    if (sess->session.name) {
        cJSON_AddStringToObject(root, "dnn", sess->session.name);
    }

    /* Add S-NSSAI */
    snssai = cJSON_CreateObject();
    if (snssai) {
        cJSON_AddNumberToObject(snssai, "sst", sess->s_nssai.sst);
        if (sess->s_nssai.sd.v != OGS_S_NSSAI_NO_SD_VALUE) {
            cJSON_AddNumberToObject(snssai, "sd", sess->s_nssai.sd.v);
        }
        cJSON_AddItemToObject(root, "s_nssai", snssai);
    }

    /* Add PDU session ID */
    cJSON_AddNumberToObject(root, "pdu_session_id", sess->psi);

    /* Add assigned IP addresses */
    assigned_ips = cJSON_CreateObject();
    if (assigned_ips) {
        if (sess->ipv4) {
            ogs_inet_ntop(&sess->ipv4->addr, ipv4_str, sizeof(ipv4_str));
            cJSON_AddStringToObject(assigned_ips, "ipv4", ipv4_str);
        }

        if (sess->ipv6) {
            ogs_inet_ntop(&sess->ipv6->addr, ipv6_str, sizeof(ipv6_str));
            cJSON_AddStringToObject(assigned_ips, "ipv6", ipv6_str);
            cJSON_AddNumberToObject(assigned_ips, "ipv6_prefix_length",
                                    OGS_IPV6_DEFAULT_PREFIX_LEN);
        }

        cJSON_AddItemToObject(root, "assigned_ips", assigned_ips);
    }

    /* Add network type (EPC or 5GC) */
    cJSON_AddStringToObject(root, "network_type", sess->epc ? "epc" : "5gc");

    /* Convert to string */
    payload_str = cJSON_PrintUnformatted(root);

    /* Cleanup */
    cJSON_Delete(root);

    return payload_str;
}

/* Send webhook notification for IP assignment */
void smf_webhook_send_ip_assigned(smf_sess_t *sess)
{
    smf_context_t *smf_ctx = NULL;
    smf_ue_t *smf_ue = NULL;
    CURL *curl = NULL;
    CURLcode res;
    char *payload = NULL;
    struct curl_slist *headers = NULL;
    char auth_header[512];
    long response_code = 0;

    ogs_assert(sess);
    smf_ctx = smf_self();
    ogs_assert(smf_ctx);

    /* Check if webhook is enabled */
    if (!smf_ctx->webhook.enabled || !smf_ctx->webhook.url) {
        return;
    }

    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    if (!smf_ue) {
        ogs_error("Cannot find SMF UE for webhook");
        return;
    }

    ogs_debug("Sending webhook notification for UE [%s]",
              smf_ue->supi ? smf_ue->supi :
              (smf_ue->imsi_bcd ? smf_ue->imsi_bcd : "unknown"));

    /* Build JSON payload */
    payload = build_webhook_payload(sess);
    if (!payload) {
        ogs_error("Failed to build webhook payload for UE [%s]",
                  smf_ue->supi ? smf_ue->supi :
                  (smf_ue->imsi_bcd ? smf_ue->imsi_bcd : "unknown"));
        return;
    }

    /* Initialize curl */
    curl = curl_easy_init();
    if (!curl) {
        ogs_error("Failed to initialize curl for webhook");
        cJSON_free(payload);
        return;
    }

    /* Set URL */
    curl_easy_setopt(curl, CURLOPT_URL, smf_ctx->webhook.url);

    /* Set POST method */
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    /* Set payload */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);

    /* Set Content-Type header */
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Add Authorization header if configured */
    if (smf_ctx->webhook.auth_header) {
        snprintf(auth_header, sizeof(auth_header), "Authorization: %s",
                 smf_ctx->webhook.auth_header);
        headers = curl_slist_append(headers, auth_header);
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* Set timeout */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)smf_ctx->webhook.timeout_ms);

    /* Set SSL verification */
    if (!smf_ctx->webhook.verify_ssl) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    /* Set write callback to discard response */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, webhook_write_callback);

    /* Perform the request */
    res = curl_easy_perform(curl);

    /* Check result */
    if (res != CURLE_OK) {
        ogs_error("Webhook notification failed for UE [%s]: %s",
                  smf_ue->supi ? smf_ue->supi :
                  (smf_ue->imsi_bcd ? smf_ue->imsi_bcd : "unknown"),
                  curl_easy_strerror(res));
    } else {
        /* Get HTTP response code */
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

        if (response_code >= 200 && response_code < 300) {
            ogs_info("Webhook notification sent for UE [%s] to %s: HTTP %ld",
                     smf_ue->supi ? smf_ue->supi :
                     (smf_ue->imsi_bcd ? smf_ue->imsi_bcd : "unknown"),
                     smf_ctx->webhook.url, response_code);
        } else {
            ogs_warn("Webhook notification completed with HTTP %ld for UE [%s]",
                     response_code,
                     smf_ue->supi ? smf_ue->supi :
                     (smf_ue->imsi_bcd ? smf_ue->imsi_bcd : "unknown"));
        }
    }

    /* Cleanup */
    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    cJSON_free(payload);
}

/* Build JSON payload for webhook deallocation notification */
static char *build_webhook_deallocation_payload(smf_sess_t *sess)
{
    smf_ue_t *smf_ue = NULL;
    cJSON *root = NULL;
    cJSON *deallocated_ips = NULL;
    cJSON *snssai = NULL;
    char *payload_str = NULL;
    char ipv4_str[OGS_ADDRSTRLEN];
    char ipv6_str[OGS_ADDRSTRLEN];
    char timestamp[64];
    time_t now;
    struct tm *tm_info;

    ogs_assert(sess);
    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);

    if (!smf_ue) {
        ogs_error("Cannot find SMF UE for webhook deallocation payload");
        return NULL;
    }

    /* Create JSON root object */
    root = cJSON_CreateObject();
    if (!root) {
        ogs_error("Failed to create JSON object for webhook deallocation");
        return NULL;
    }

    /* Add event type */
    cJSON_AddStringToObject(root, "event", "ue_ip_deallocated");

    /* Add timestamp (ISO 8601 format) */
    time(&now);
    tm_info = gmtime(&now);
    if (tm_info) {
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm_info);
        cJSON_AddStringToObject(root, "timestamp", timestamp);
    }

    /* Add SUPI (if available) */
    if (smf_ue->supi) {
        cJSON_AddStringToObject(root, "supi", smf_ue->supi);
    }

    /* Add IMSI */
    if (smf_ue->imsi_bcd && smf_ue->imsi_bcd[0]) {
        cJSON_AddStringToObject(root, "imsi", smf_ue->imsi_bcd);
    }

    /* Add DNN/APN */
    if (sess->session.name) {
        cJSON_AddStringToObject(root, "dnn", sess->session.name);
    }

    /* Add S-NSSAI */
    snssai = cJSON_CreateObject();
    if (snssai) {
        cJSON_AddNumberToObject(snssai, "sst", sess->s_nssai.sst);
        if (sess->s_nssai.sd.v != OGS_S_NSSAI_NO_SD_VALUE) {
            cJSON_AddNumberToObject(snssai, "sd", sess->s_nssai.sd.v);
        }
        cJSON_AddItemToObject(root, "s_nssai", snssai);
    }

    /* Add PDU session ID */
    cJSON_AddNumberToObject(root, "pdu_session_id", sess->psi);

    /* Add deallocated IP addresses */
    deallocated_ips = cJSON_CreateObject();
    if (deallocated_ips) {
        if (sess->ipv4) {
            ogs_inet_ntop(&sess->ipv4->addr, ipv4_str, sizeof(ipv4_str));
            cJSON_AddStringToObject(deallocated_ips, "ipv4", ipv4_str);
        }

        if (sess->ipv6) {
            ogs_inet_ntop(&sess->ipv6->addr, ipv6_str, sizeof(ipv6_str));
            cJSON_AddStringToObject(deallocated_ips, "ipv6", ipv6_str);
            cJSON_AddNumberToObject(deallocated_ips, "ipv6_prefix_length",
                                    OGS_IPV6_DEFAULT_PREFIX_LEN);
        }

        cJSON_AddItemToObject(root, "deallocated_ips", deallocated_ips);
    }

    /* Add network type (EPC or 5GC) */
    cJSON_AddStringToObject(root, "network_type", sess->epc ? "epc" : "5gc");

    /* Convert to string */
    payload_str = cJSON_PrintUnformatted(root);

    /* Cleanup */
    cJSON_Delete(root);

    return payload_str;
}

/* Send webhook notification for IP deallocation */
void smf_webhook_send_ip_deallocated(smf_sess_t *sess)
{
    smf_context_t *smf_ctx = NULL;
    smf_ue_t *smf_ue = NULL;
    CURL *curl = NULL;
    CURLcode res;
    char *payload = NULL;
    struct curl_slist *headers = NULL;
    char auth_header[512];
    long response_code = 0;

    ogs_assert(sess);
    smf_ctx = smf_self();
    ogs_assert(smf_ctx);

    /* Check if webhook is enabled */
    if (!smf_ctx->webhook.enabled || !smf_ctx->webhook.url) {
        return;
    }

    /* Check if IPs exist before trying to send deallocation notification */
    if (!sess->ipv4 && !sess->ipv6) {
        ogs_debug("No IPs to deallocate for session");
        return;
    }

    smf_ue = smf_ue_find_by_id(sess->smf_ue_id);
    if (!smf_ue) {
        ogs_error("Cannot find SMF UE for webhook deallocation");
        return;
    }

    ogs_debug("Sending webhook deallocation notification for UE [%s]",
              smf_ue->supi ? smf_ue->supi :
              (smf_ue->imsi_bcd ? smf_ue->imsi_bcd : "unknown"));

    /* Build JSON payload */
    payload = build_webhook_deallocation_payload(sess);
    if (!payload) {
        ogs_error("Failed to build webhook deallocation payload for UE [%s]",
                  smf_ue->supi ? smf_ue->supi :
                  (smf_ue->imsi_bcd ? smf_ue->imsi_bcd : "unknown"));
        return;
    }

    /* Initialize curl */
    curl = curl_easy_init();
    if (!curl) {
        ogs_error("Failed to initialize curl for webhook deallocation");
        cJSON_free(payload);
        return;
    }

    /* Set URL */
    curl_easy_setopt(curl, CURLOPT_URL, smf_ctx->webhook.url);

    /* Set POST method */
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    /* Set payload */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);

    /* Set Content-Type header */
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Add Authorization header if configured */
    if (smf_ctx->webhook.auth_header) {
        snprintf(auth_header, sizeof(auth_header), "Authorization: %s",
                 smf_ctx->webhook.auth_header);
        headers = curl_slist_append(headers, auth_header);
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* Set timeout */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)smf_ctx->webhook.timeout_ms);

    /* Set SSL verification */
    if (!smf_ctx->webhook.verify_ssl) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    /* Set write callback to discard response */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, webhook_write_callback);

    /* Perform the request */
    res = curl_easy_perform(curl);

    /* Check result */
    if (res != CURLE_OK) {
        ogs_error("Webhook deallocation notification failed for UE [%s]: %s",
                  smf_ue->supi ? smf_ue->supi :
                  (smf_ue->imsi_bcd ? smf_ue->imsi_bcd : "unknown"),
                  curl_easy_strerror(res));
    } else {
        /* Get HTTP response code */
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

        if (response_code >= 200 && response_code < 300) {
            ogs_info("Webhook deallocation notification sent for UE [%s] to %s: HTTP %ld",
                     smf_ue->supi ? smf_ue->supi :
                     (smf_ue->imsi_bcd ? smf_ue->imsi_bcd : "unknown"),
                     smf_ctx->webhook.url, response_code);
        } else {
            ogs_warn("Webhook deallocation notification completed with HTTP %ld for UE [%s]",
                     response_code,
                     smf_ue->supi ? smf_ue->supi :
                     (smf_ue->imsi_bcd ? smf_ue->imsi_bcd : "unknown"));
        }
    }

    /* Cleanup */
    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    cJSON_free(payload);
}
