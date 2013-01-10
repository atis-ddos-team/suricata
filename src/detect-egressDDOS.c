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
#include <sys/time.h>
#include "detect-engine.h"
#include "detect.h"
#include "detect-parse.h"

#include "detect-egressDDOS.h"
#include "util-debug.h"

#include "host.h"

#include "math.h"

/*prototypes*/
int DetecteDDOSMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
static int DetecteDDOSSetup(DetectEngineCtx *, Signature *, char *);
void DetecteDDOSFree(void *);
void DetecteDDOSRegisterTests(void);
uint64_t tcp_pkts_gesamt = 0;
uint64_t udp_pkt_gesamt = 0;
uint64_t tcp_fin_ack_gesamt = 0;
uint64_t tcp_syn_ack_gesamt = 0;
uint64_t tcp_syn_gesamt = 0;
uint64_t icmp_gesamt = 0;
time_t start_time = 0;
uint8_t tcp_syn_ack_flag = 18;
uint8_t tcp_fin_ack_flag = 17;



/**
 *  * \brief Regex for parsing our keyword options
 *   */
#define PARSE_REGEX  "^\\s*([0-9]+\\.[0-9]+)\\s*,s*([0-9]+\\.[0-9]+)\\s*,s*([0-9]+\\.[0-9]+)\\s*$" 

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
    /**
     * Start counting for evaluation
     */
    (ddata->cnt_packets)++;

    if (PKT_IS_TCP(p)) {
        //counter host
        (ddata->cnt_tcp)++;
        //counter global
        tcp_pkts_gesamt++;
        //printf("\nPakets TCP Flag: %d\n", p->tcph->th_flags);
        if (p->tcph->th_flags == tcp_syn_ack_flag) {
            (ddata->cnt_tcp_syn_ack)++;
            tcp_syn_ack_gesamt++;
            //printf("TCP_SYN_ACK");
        }
        if (p->tcph->th_flags == tcp_fin_ack_flag) {
            (ddata->cnt_tcp_fin_ack)++;
            tcp_fin_ack_gesamt++;
            //printf("TCP_FIN_ACK");
        }
        if (p->tcph->th_flags == TH_SYN) {
            (ddata->cnt_tcp_syn)++;
            tcp_syn_gesamt++;
            //printf("TCP_SYN");

        }
    }

    if (PKT_IS_UDP(p)) {
        (ddata->cnt_udp)++;
        udp_pkt_gesamt++;
    }

    if (PKT_IS_ICMPV4(p) && p->icmpv4h->type == ICMP_ECHO) {
        (ddata->cnt_icmp_echo_req)++;
        icmp_gesamt++;
    }

    /**
     * End Counting
     */
    /**
     * Start evaluation
     */
    if (PKT_IS_UDP(p) || PKT_IS_TCP(p)) {
        t1 = p->ts.tv_sec;
        time_diff_ms = difftime(t1, ddata->PeriodStart);
        if (time_diff_ms > (120)) {
            /*check for alarm here*/
            // abweichung vom 1:2 verhältnis SYN/ACK zu FIN/ACK
            float ver_syn_ack;
            float abw_syn_ack;
            // verhältnis von ICMP echo req paketen zu allen paketen
            float ver_echoreq_norm;
            // verhältnis von udp pakten zu allen paketen
            float ver_udp_norm;
            if (ddata->cnt_tcp_fin_ack != 0) {
                ver_syn_ack = ((float) (ddata->cnt_tcp_syn_ack) / ddata->cnt_tcp_fin_ack);
            } else {
                // we have syn but no syn_acks
                if (((ddata->cnt_tcp_syn - ddata->cnt_tcp_syn_ack)*2) > dsig->max_abweichung_syn_ack) {
                    ver_syn_ack = -1;
                }
                ver_syn_ack = 0;
            }

            abw_syn_ack = (((1 / 2) - ver_syn_ack))*2;
            //printf("\nSYN/ACK zu FIN/ACK Host Value: %f # SYN/ACK: %llu - FIN/ACK: %llu\n", (abw_syn_ack), ddata->cnt_tcp_syn_ack, ddata->cnt_tcp_fin_ack);

            if (abw_syn_ack < 0) {

                // check if abweichung größer als in signatur angegeben
                if (fabs(abw_syn_ack) > dsig->max_abweichung_syn_ack) {
                    ret = 1;
                    printf("\nSYN/ACK zu FIN/ACK Host Value: %f # SYN/ACK: %llu - FIN/ACK: %llu\n", (abw_syn_ack), ddata->cnt_tcp_syn_ack, ddata->cnt_tcp_fin_ack);

                }
            }


            // verhältnis icmp echo request berechnen
            ver_echoreq_norm = ((float) (ddata->cnt_icmp_echo_req) / ddata->cnt_packets)*100;

            // check if ICMP echo request pakete zu viel im verhältnis zu allen
            if (ver_echoreq_norm > (float) (dsig->max_icmp_echo_req_packets)) {
                ret = 1;
                printf("\nICMP Host\n");
            }
            /**
            // verhältnis udp paketen berechnen
            ver_udp_norm = ((float)(ddata->cnt_udp) / ddata->cnt_packets);
            // check if udp pakete zu viel im verhältnis zu allen
            if ( ver_udp_norm > (float)(dsig->max_udp_packets) ) {
                ret = 1;
            }  
             */
            /**
             * gesamtauswertung 
             */
            time_diff_ms = difftime(t1, start_time);
            if (time_diff_ms > (60)) {
                // auswertung udp pakete
                // verhältnis udp paketen berechnen
                ver_udp_norm = ((float) (udp_pkt_gesamt) / (udp_pkt_gesamt + tcp_pkts_gesamt))*100;
                //printf("UDP Pakete Verhaeltnis: %f", ver_udp_norm);
                // check if udp pakete zu viel im verhältnis zu allen
                if (ver_udp_norm > (float) (dsig->max_verhaeltnis_udp_packets)) {
                    ret = 1;
                    printf("\nUDP ALL\n");
                }

                // auswertung echo requests
                ver_echoreq_norm = ((float) (icmp_gesamt) / (udp_pkt_gesamt + tcp_pkts_gesamt))*100;
                if (ver_echoreq_norm > (float) (icmp_gesamt)) {
                    ret = 1;
                    printf("\nICMP ALL\n");
                }

                // auswertung syn/ack
                if (tcp_fin_ack_gesamt != 0) {
                    ver_syn_ack = ((float) (tcp_syn_ack_gesamt) / tcp_fin_ack_gesamt);
                } else {
                    // we have syn but no syn_acks
                    if (((ddata->cnt_tcp_syn - ddata->cnt_tcp_syn_ack)*2) > dsig->max_abweichung_syn_ack) {
                        ver_syn_ack = -1;
                    }
                    ver_syn_ack = 0;
                }

                abw_syn_ack = (((1 / 2) - ver_syn_ack))*2;
                if (abw_syn_ack < 0) {
                    // check if abweichung größer als in signatur angegeben
                    if (fabs(abw_syn_ack) > dsig->max_abweichung_syn_ack) {
                        ret = 1;
                        printf("\nSYN/ACK zu FIN/ACK ALL\n");
                    }
                }
                // reset global counter for new interval
                
                tcp_pkts_gesamt = 0;
                udp_pkt_gesamt = 0;
                tcp_fin_ack_gesamt = 0;
                tcp_syn_ack_gesamt = 0;
                icmp_gesamt = 0;
                


            }
            /**printf("host found, packets now %d\n", (int)(ddata->cnt_packets));
            ret = (ddata->cnt_packets > dsig->max_numpackets);
             */

            // reset der parameter, da neuer zeitraum beginnt
            ddata->PeriodStart = p->ts.tv_sec;
            ddata->cnt_icmp_echo_req = 0;
            ddata->cnt_packets = 0;
            ddata->cnt_tcp = 0;
            ddata->cnt_tcp_fin_ack = 0;
            ddata->cnt_tcp_syn_ack = 0;
            ddata->cnt_udp = 0;

        } else {
            ret = 0;
        }
    }
    /**
     * End of evaluation
     */

    //printf("\nHost: %d - %d\n", (int)h, ddata->cnt_packets);
    /**
    printf("#################################\n");
    printf("Host: %d\n",(int)h);
    printf("\n TCP-SYN: %d \n", ddata->cnt_tcp_syn);
    printf("\n TCP-ACK: %d \n", ddata->cnt_tcp_ack);
    printf("\n Packets gesamt: %d \n", ddata->cnt_packets);
    printf("\n Packets TCP gesamt: %d \n", ddata->cnt_tcp);
    printf("\n Packets UDP gesamt: %d \n", ddata->cnt_udp);
    printf("\n ICMP ECHO REQUEST Packets: %d \n", ddata->cnt_icmp_echo_req);
    printf("#################################\n");
    
    printf("\n\nTCP Gesamt: %llu\n",tcp_pkts_gesamt);
    printf("UDP Gesamt: %llu\n",udp_pkt_gesamt);
    printf("SYN: %llu\n",tcp_syn_gesamt);
    printf("ICMP: %llu\n",icmp_gesamt);
    printf("SYN_ACK gesamt %d\n",(int)tcp_syn_ack_gesamt);
    printf("FIN_ACK_gesamt %d\n\n",(int)tcp_fin_ack_gesamt);
    */
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

DetecteDDOSSig *DetecteDDOSParse(char *eDDOSstr) {
    DetecteDDOSSig *eDDOSd = NULL;
    char *arg1 = NULL;
    char *arg2 = NULL;
    char *arg3 = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, eDDOSstr, strlen(eDDOSstr), 0, 0, ov, MAX_SUBSTRINGS);
    //printf("\n%s\n", eDDOSstr);
    if (ret != 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }
    const char *str_ptr;
    // parse first paremeter "arg1" SYN/ACK abweichung
    res = pcre_get_substring((char *) eDDOSstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    //printf("\n%s\n",(char *) str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    arg1 = (char *) str_ptr;
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        /**
         * parse second parameter "arg2" ICMP "port unreachable"
         */
        res = pcre_get_substring((char *) eDDOSstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }
        arg2 = (char *) str_ptr;
        SCLogDebug("Arg2 \"%s\"", arg2);


        /**
         * parse third parameter "arg3" ICMP "echo request"
         */
        res = pcre_get_substring((char *) eDDOSstr, ov, MAX_SUBSTRINGS, 3, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }
        arg3 = (char *) str_ptr;
        SCLogDebug("Arg3 \"%s\"", arg3);

    }

    eDDOSd = SCMalloc(sizeof (DetecteDDOSData));
    if (unlikely(eDDOSd == NULL))
        goto error;
    eDDOSd->max_abweichung_syn_ack = atof(arg1);
    eDDOSd->max_icmp_echo_req_packets = atof(arg2);
    eDDOSd->max_verhaeltnis_udp_packets = atof(arg3);

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

#ifdef UNITTESTS

/**
 * test description of the test
 */

static int DetecteDDOSParseTest01(void) {
    DetecteDDOSSig *eDDOSd = NULL;
    uint8_t res = 0;

    eDDOSd = DetecteDDOSParse("1.0,1.0,1.0");
    if (eDDOSd != NULL) {
        /**
         * test first arg. as c can not test equals a float value we test against range
         */
        if (eDDOSd->max_abweichung_syn_ack > 0.5 && eDDOSd->max_abweichung_syn_ack < 1.5 && eDDOSd->max_icmp_echo_req_packets > 0.5 && eDDOSd->max_icmp_echo_req_packets < 1.5 && eDDOSd->max_verhaeltnis_udp_packets > 0.5 && eDDOSd->max_verhaeltnis_udp_packets < 1.5) {
            res = 1;
        }


        DetecteDDOSFree(eDDOSd);
    }

    return res;
}

static int DetecteDDOSSignatureTest01(void) {
    uint8_t res = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (eDDOS:10.1,10.1,10.1; sid:1; rev:1;)");
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
