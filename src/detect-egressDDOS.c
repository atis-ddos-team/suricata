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
 * \author ATIS-DDOS-TEAM
 *
 * Implements some basic egress DDOS detection. 
 * Currently trys to detect UDP-,SYN- and Echo-Floods. 
 */

#include "suricata-common.h"
#include "stream-tcp.h"
#include "util-unittest.h"
#include "decode-icmpv4.h"
#include "detect-flags.h"
#include <time.h>
#include "detect-engine.h"
#include "detect.h"
#include "detect-parse.h"

#include "detect-egressDDOS.h"
#include "util-debug.h"

#include "host.h"

/*prototypes*/
int DetecteDDOSMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
static int DetecteDDOSSetup(DetectEngineCtx *, Signature *, char *);
void DetecteDDOSFree(void *);
void DetecteDDOSRegisterTests(void);


/**
 *  * \brief Regex for parsing our keyword options
 *   */
#define PARSE_REGEX  "^\\s*([0-9]+)?\\s*,s*([0-9]+)?\\s*$" 

static pcre *parse_regex;
static pcre_extra *parse_regex_study;


/**
 * \brief Registration function for `eDDOS` keyword
 */

void DetecteDDOSRegister(void) {
    sigmatch_table[DETECT_EDDOS].name = "eDDOS";
    sigmatch_table[DETECT_EDDOS].Match = DetecteDDOSMatch;
    sigmatch_table[DETECT_EDDOS].Setup = DetecteDDOSSetup;
    sigmatch_table[DETECT_EDDOS].Free = DetecteDDOSFree;
    sigmatch_table[DETECT_EDDOS].RegisterTests = DetecteDDOSRegisterTests;

    const char *eb;
    int eo;
    int opts = 0;
    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }
    return;

error:
    if (parse_regex != NULL)
        SCFree(parse_regex);
    if (parse_regex_study != NULL)
        SCFree(parse_regex_study);
     return;
}

/**
 * \brief This function is used to match packets via the eDDOS rule
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectDummyData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetecteDDOSMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, SigMatch *m) {

    int ret = 0;
    DetecteDDOSSig *dsig = (DetecteDDOSSig *) m->ctx;
    DetecteDDOSData *ddata;
    Host *h;
    time_t t1;
    double time_diff_ms;

    if (PKT_IS_PSEUDOPKT(p)
            || !PKT_IS_IPV4(p)
            || p->flags & PKT_HOST_SRC_LOOKED_UP) {
        return 0;
    }

    /* TODO: Inspect the packet contents here.
     * Suricata defines a `Packet` structure in decode.h which already defines 
     * many useful elements -- have a look! */

    h = HostGetHostFromHash(&(p->src)); // Only SRC or can DEST be used too?
    p->flags |= PKT_HOST_SRC_LOOKED_UP;

    if (h == NULL) {
        printf("host not found!\n");
        return 0;
    }

    ddata = (DetecteDDOSData *) h->eddos;
    if (!ddata) {
        /* initialize fresh dummydata */
        ddata = SCMalloc(sizeof (DetecteDDOSData));
        bzero(ddata, sizeof (DetecteDDOSData));
        h->eddos = ddata;
    }

    (ddata->cnt_packets)++;

    if (PKT_IS_TCP(p)) {
        (ddata->cnt_tcp)++;
        if (p->tcph->th_flags == TH_ACK) {
            (ddata->cnt_tcp_ack)++;
        }
        if (p->tcph->th_flags == TH_SYN) {
            (ddata->cnt_tcp_syn)++;
        }
    }



    if (PKT_IS_UDP(p)) {
        (ddata->cnt_udp)++;
    }

    if (PKT_IS_ICMPV4(p) && p->icmpv4h->type == ICMP_ECHO) {
        (ddata->cnt_icmp_echo_req)++;
    }


    t1 = time(0);
    time_diff_ms = difftime(t1, dsig->PeriodStart) * 1000.;
    if (time_diff_ms > (100 * 60 * 60)) {
        /*check for alarm here*/
        printf("host found, packets now %d\n", (int)(ddata->cnt_packets));
        ret = (ddata->cnt_packets > dsig->max_numpackets);
        dsig->PeriodStart = time(0);
    } else {
        ret = 0;
    }


    HostRelease(h);
    return ret;
}

/**
 * \brief This function is used to parse eDDOS options passed via eDDOS: keyword
 *
 * \param eDDOSstr Pointer to the user provided eDDOS options
 *
 * \retval eDDOSd pointer to DetecteDDODSSig on success
 * \retval NULL on failure
 */

DetecteDDOSSig *DetecteDDOSParse (char *eDDOSstr)
{
    DetecteDDOSSig *eDDOSd = NULL;
    char *arg1 = NULL;
    char *arg2 = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, eDDOSstr, strlen(eDDOSstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }
    const char *str_ptr;

    res = pcre_get_substring((char *) eDDOSstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    arg1 = (char *) str_ptr;
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        res = pcre_get_substring((char *) eDDOSstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }
        arg2 = (char *) str_ptr;
        SCLogDebug("Arg2 \"%s\"", arg2);

    }

    eDDOSd = SCMalloc(sizeof (DetecteDDOSData));
    if (unlikely(eDDOSd == NULL))
        goto error;
    eDDOSd->max_tcppackets = (uint64_t)atoi(arg1);
    eDDOSd->max_udppackets = (uint64_t)atoi(arg2);

    SCFree(arg1);
    SCFree(arg2);
    return eDDOSd;

error:
    if (eDDOSd)
        SCFree(eDDOSd);
    if (arg1)
        SCFree(arg1);
    if (arg2)
        SCFree(arg2);
    return NULL;
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
static int DetecteDDOSSetup(DetectEngineCtx *de_ctx, Signature *s, char *ddosstr) {

    SigMatch *sm = NULL;
    DetecteDDOSSig *dsig = NULL;

    dsig = SCMalloc(sizeof (DetecteDDOSSig));
    if (dsig == NULL) {
        goto error;
    }

    sm = SigMatchAlloc();
    if (sm == NULL) {
        goto error;
    }


    //dsig->PeriodStart = time(0);
    //dsig->max_numpackets = atoi(dummystr);
    /**
     * Parse the ddosstring for option keywords
     */
    dsig = DetecteDDOSParse(ddosstr);

    sm->type = DETECT_EDDOS;
    sm->ctx = (void *) dsig;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;

error:
    if (dsig != NULL) SCFree(dsig);
    if (sm != NULL) SCFree(sm);
    return -1;
}

void DetecteDDOSFree(void *ptr) {
    DetecteDDOSData *ed = (DetecteDDOSData*) ptr;
    SCFree(ed);
}

//void DetecteDDOSRegisterTests(void) {
#ifdef UNITTESTS

/**
 * \test description of the test
 */

static int DetecteDDOSParseTest01 (void) {
    DetecteDDOSSig *eDDOSd = NULL;
    uint8_t res = 0;

    eDDOSd = DetecteDDOSParse("1,10");
    if (eDDOSd != NULL) {
        if (eDDOSd->max_tcppackets == 1 && eDDOSd->max_udppackets == 10)
            res = 1;

        DetecteDDOSFree(eDDOSd);
    }

    return res;
}

static int DetecteDDOSSignatureTest01 (void) {
    uint8_t res = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (eDDOS:1,10; sid:1; rev:1;)");
    if (sig == NULL) {
        printf("parsing signature failed: ");
        goto end;
    }

    /* if we get here, all conditions pass */
    res = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return res;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetecteDDOS
 */
void DetecteDDOSRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DetecteDDOSParseTest01", DetecteDDOSParseTest01, 1);
    UtRegisterTest("DetecteDDOSSignatureTest01", DetecteDDOSSignatureTest01, 1);
#endif /* UNITTESTS */
}
//}
