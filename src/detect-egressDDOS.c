/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Christian Rossow <christian.rossow [at] gmail.com>
 *
 * Implements the dummy keyword
 */

#include "suricata-common.h"
#include "stream-tcp.h"
#include "util-unittest.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-egressDDOS.h"
#include "util-debug.h"

#include "host.h"

/*prototypes*/
int DetecteDDOSMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
static int DetecteDDOSSetup (DetectEngineCtx *, Signature *, char *);
void DetecteDDOSFree (void *);
void DetectDummyRegisterTests (void);

/**
 * \brief Registration function for `dummy` keyword
 */

void DetecteDDOSRegister(void) {
    sigmatch_table[DETECT_EDDOS].name = "eDDOS";
    sigmatch_table[DETECT_EDDOS].Match = DetecteDDOSMatch;
    sigmatch_table[DETECT_EDDOS].Setup = DetecteDDOSSetup;
    sigmatch_table[DETECT_EDDOS].Free = DetecteDDOSFree;
    sigmatch_table[DETECT_EDDOS].RegisterTests = DetecteDDOSRegisterTests;
}

/**
 * \brief This function is used to match packets via the dummy rule
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectDummyData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetecteDDOSMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, SigMatch *m) {

    int ret = 0;
    DetectDummySig *dsig = (DetectDummySig *) m->ctx;
    DetectDummyData *ddata;
    Host *h;

    if (PKT_IS_PSEUDOPKT(p)
        || !PKT_IS_IPV4(p)
        || p->flags & PKT_HOST_SRC_LOOKED_UP
        || p->payload_len == 0) {
        return 0;
    }

    /* TODO: Inspect the packet contents here.
     * Suricata defines a `Packet` structure in decode.h which already defines 
     * many useful elements -- have a look! */

    h = HostGetHostFromHash(&(p->src));
    p->flags |= PKT_HOST_SRC_LOOKED_UP;

    if (h == NULL) {
        printf("host not found!\n");
        return 0;
    }

    ddata = (DetectDummyData *) h->dummy;
    if (!ddata) {
        /* initialize fresh dummydata */
        ddata = SCMalloc(sizeof(DetectDummyData));
        bzero(ddata, sizeof(DetectDummyData));
        h->dummy = ddata;
    }
    
    (ddata->cnt_packets)++;
    //printf("host found, packets now %d\n", ddata->cnt_packets);
    ret = (ddata->cnt_packets > dsig->max_numpackets);
    
    HostRelease(h);
    return ret;
}

/**
 * \brief this function is used to setup the dummy environment
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param dummystr pointer to the user provided dummy options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetecteDDOSSetup (DetectEngineCtx *de_ctx, Signature *s, char *dummystr) {

    SigMatch *sm = NULL;
    DetectDummySig *dsig = NULL;
    
    dsig = SCMalloc(sizeof(DetectDummySig));
    if (dsig == NULL) { goto error; }

    sm = SigMatchAlloc();
    if (sm == NULL) { goto error; }

    dsig->max_numpackets = atoi(dummystr);

    sm->type = DETECT_DUMMY;
    sm->ctx = (void *) dsig;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;

error:
    if (dsig != NULL) SCFree(dsig);
    if (sm != NULL) SCFree(sm);
    return -1;
}

void DetecteDDOSFree (void *ptr) {
    DetecteDDOSData *ed = (DetecteDDOSData*) ptr;
    SCFree(ed);
}

void DetecteDDOSRegisterTests(void) {
    #ifdef UNITTESTS
    // TODO
    #endif
}
