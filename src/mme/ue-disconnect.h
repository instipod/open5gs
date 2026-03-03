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

#ifndef MME_UE_DISCONNECT_H
#define MME_UE_DISCONNECT_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Action handler for GET /ue-disconnect?imsi=<IMSI>
 *
 * Initiates an MME-implicit UE detach (S1AP UEContextReleaseCommand +
 * GTP session deletion) for the UE identified by the given IMSI.
 *
 * Returns a JSON response body written into buf.
 */
size_t mme_ue_disconnect_action(void *conn, char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* MME_UE_DISCONNECT_H */
