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

#include "ogs-webhook.h"

#include <curl/curl.h>
#include <string.h>

static size_t webhook_write_callback(
        void *contents, size_t size, size_t nmemb, void *userp)
{
    return size * nmemb;
}

void ogs_webhook_config_init(ogs_webhook_config_t *config)
{
    ogs_assert(config);
    memset(config, 0, sizeof(*config));
    config->timeout_ms = 5000;
    config->verify_ssl = true;
}

int ogs_webhook_config_parse_yaml(
        ogs_webhook_config_t *config, ogs_yaml_iter_t *parent_iter)
{
    ogs_yaml_iter_t webhook_iter;

    ogs_assert(config);
    ogs_assert(parent_iter);

    ogs_yaml_iter_recurse(parent_iter, &webhook_iter);

    while (ogs_yaml_iter_next(&webhook_iter)) {
        const char *webhook_key = ogs_yaml_iter_key(&webhook_iter);
        ogs_assert(webhook_key);

        if (!strcmp(webhook_key, "url")) {
            config->url = ogs_yaml_iter_value(&webhook_iter);
            if (config->url && strlen(config->url) > 0) {
                config->enabled = 1;
            }
        } else if (!strcmp(webhook_key, "enabled")) {
            config->enabled = ogs_yaml_iter_bool(&webhook_iter);
        } else if (!strcmp(webhook_key, "timeout")) {
            const char *v = ogs_yaml_iter_value(&webhook_iter);
            if (v) config->timeout_ms = atoi(v);
        } else if (!strcmp(webhook_key, "verify_ssl")) {
            config->verify_ssl = ogs_yaml_iter_bool(&webhook_iter);
        } else if (!strcmp(webhook_key, "auth_header")) {
            config->auth_header = ogs_yaml_iter_value(&webhook_iter);
        } else {
            ogs_warn("unknown webhook key `%s`", webhook_key);
        }
    }

    return OGS_OK;
}

int ogs_webhook_config_validate(ogs_webhook_config_t *config)
{
    ogs_assert(config);

    if (config->enabled && !config->url) {
        ogs_error("Webhook enabled but no URL configured");
        return OGS_ERROR;
    }

    if (config->url && strlen(config->url) > 0) {
        if (strncmp(config->url, "http://", 7) != 0 &&
            strncmp(config->url, "https://", 8) != 0) {
            ogs_error("Invalid webhook URL "
                    "(must start with http:// or https://): %s", config->url);
            return OGS_ERROR;
        }
    }

    return OGS_OK;
}

int ogs_webhook_send(
        ogs_webhook_config_t *config,
        const char *payload, const char *log_label)
{
    CURL *curl = NULL;
    CURLcode res;
    struct curl_slist *headers = NULL;
    char auth_header_buf[512];
    long response_code = 0;

    ogs_assert(config);
    ogs_assert(payload);

    if (!config->enabled || !config->url) {
        return OGS_OK;
    }

    curl = curl_easy_init();
    if (!curl) {
        ogs_error("Failed to initialize curl for webhook");
        return OGS_ERROR;
    }

    curl_easy_setopt(curl, CURLOPT_URL, config->url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);

    headers = curl_slist_append(headers, "Content-Type: application/json");

    if (config->auth_header) {
        snprintf(auth_header_buf, sizeof(auth_header_buf),
                "Authorization: %s", config->auth_header);
        headers = curl_slist_append(headers, auth_header_buf);
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)config->timeout_ms);

    if (!config->verify_ssl) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, webhook_write_callback);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        ogs_error("Webhook failed [%s]: %s",
                log_label ? log_label : "unknown",
                curl_easy_strerror(res));
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

        if (response_code >= 200 && response_code < 300) {
            ogs_info("Webhook sent [%s] to %s: HTTP %ld",
                    log_label ? log_label : "unknown",
                    config->url, response_code);
        } else {
            ogs_warn("Webhook completed with HTTP %ld [%s]",
                    response_code,
                    log_label ? log_label : "unknown");
        }
    }

    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK) ? OGS_OK : OGS_ERROR;
}
