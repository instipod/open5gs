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

#ifndef MME_WEBHOOK_H
#define MME_WEBHOOK_H

#include "mme-context.h"

#ifdef __cplusplus
extern "C" {
#endif

void mme_webhook_send_enb_attached(mme_enb_t *enb);
void mme_webhook_send_enb_detached(mme_enb_t *enb);
void mme_webhook_send_ue_attached(mme_ue_t *mme_ue);
void mme_webhook_send_ue_detached(mme_ue_t *mme_ue);

#ifdef __cplusplus
}
#endif

#endif /* MME_WEBHOOK_H */
