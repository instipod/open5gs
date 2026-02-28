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

#ifndef OGS_WEBHOOK_H
#define OGS_WEBHOOK_H

#include "app/ogs-app.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ogs_webhook_config_s {
    char *url;
    char *auth_header;
    int enabled;
    int timeout_ms;
    bool verify_ssl;
} ogs_webhook_config_t;

void ogs_webhook_config_init(ogs_webhook_config_t *config);
int ogs_webhook_config_parse_yaml(
        ogs_webhook_config_t *config, ogs_yaml_iter_t *parent_iter);
int ogs_webhook_config_validate(ogs_webhook_config_t *config);

int ogs_webhook_send(
        ogs_webhook_config_t *config,
        const char *payload, const char *log_label);

#ifdef __cplusplus
}
#endif

#endif /* OGS_WEBHOOK_H */
