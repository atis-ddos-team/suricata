/* Copyright (C) 2007-2012 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#include "suricata-common.h"
#include "host.h"

#include "detect-engine-tag.h"
#include "detect-engine-threshold.h"
#include "reputation.h"

uint32_t HostGetSpareCount(void) {
    return HostSpareQueueGetSize();
}

uint32_t HostGetActiveCount(void) {
    return SC_ATOMIC_GET(host_counter);
}

/** \internal
 *  \brief See if we can really discard this host. Check use_cnt reference.
 *
 *  \param h host
 *  \param ts timestamp
 *
 *  \retval 0 not timed out just yet
 *  \retval 1 fully timed out, lets kill it
 */
static int HostHostTimedOut(Host *h, struct timeval *ts) {
    return 0;
}

/**
 *  \internal
 *
 *  \brief check all hosts in a hash row for timing out
 *
 *  \param hb host hash row *LOCKED*
 *  \param h last host in the hash row
 *  \param ts timestamp
 *
 *  \retval cnt timed out hosts
 */
static uint32_t HostHashRowTimeout(HostHashRow *hb, Host *h, struct timeval *ts)
{
	return 0;
}

/**
 *  \brief time out hosts from the hash
 *
 *  \param ts timestamp
 *
 *  \retval cnt number of timed out host
 */
uint32_t HostTimeoutHash(struct timeval *ts) {	
	return 0;
}
