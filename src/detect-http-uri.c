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
 * \ingroup httplayer
 *
 * @{
 */


/**
 * \file
 *
 * \author Gerardo Iglesias  <iglesiasg@gmail.com>
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-content.h"
#include "detect-pcre.h"

#include "flow.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-spm.h"
#include "util-print.h"

#include "app-layer.h"

#include "app-layer-htp.h"
#include "detect-http-uri.h"
#include "detect-uricontent.h"
#include "stream-tcp.h"

static int DetectHttpUriSetup (DetectEngineCtx *, Signature *, char *);
void DetectHttpUriRegisterTests(void);

/**
 * \brief Registration function for keyword: http_uri
 */
void DetectHttpUriRegister (void) {
    sigmatch_table[DETECT_AL_HTTP_URI].name = "http_uri";
    sigmatch_table[DETECT_AL_HTTP_URI].desc = "content modifier to match specifically and only on the HTTP uri-buffer";
    sigmatch_table[DETECT_AL_HTTP_URI].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/HTTP-keywords#http_uri-and-http_raw_uri";
    sigmatch_table[DETECT_AL_HTTP_URI].Match = NULL;
    sigmatch_table[DETECT_AL_HTTP_URI].AppLayerMatch = NULL;
    sigmatch_table[DETECT_AL_HTTP_URI].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_AL_HTTP_URI].Setup = DetectHttpUriSetup;
    sigmatch_table[DETECT_AL_HTTP_URI].Free  = NULL;
    sigmatch_table[DETECT_AL_HTTP_URI].RegisterTests = DetectHttpUriRegisterTests;

    sigmatch_table[DETECT_AL_HTTP_URI].flags |= SIGMATCH_PAYLOAD;
}


/**
 * \brief this function setups the http_uri modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

static int DetectHttpUriSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectContentData *cd = NULL;
    SigMatch *sm = NULL;

    if (str != NULL && strcmp(str, "") != 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "http_uri shouldn't be supplied with "
                   " an argument");
        return -1;
    }

    sm =  SigMatchGetLastSMFromLists(s, 2,
                                     DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH]);
    if (sm == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "\"http_uri\" keyword "
                   "found inside the rule without a content context.  "
                   "Please use a \"content\" keyword before using the "
                   "\"http_uri\" keyword");
        return -1;
    }

    cd = (DetectContentData *)sm->ctx;

    /* http_uri should not be used with the rawbytes rule */
    if (cd->flags & DETECT_CONTENT_RAWBYTES) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "http_uri rule can not "
                   "be used with the rawbytes rule keyword");
        return -1;
    }

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_HTTP) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains a non http "
                   "alproto set");
        goto error;
    }

    if ((cd->flags & DETECT_CONTENT_WITHIN) || (cd->flags & DETECT_CONTENT_DISTANCE)) {
        SigMatch *pm =  SigMatchGetLastSMFromLists(s, 4,
                                                   DETECT_CONTENT, sm->prev,
                                                   DETECT_PCRE, sm->prev);
        /* pm can be NULL now.  To accomodate parsing sigs like -
         * content:one; http_modifier; content:two; distance:0; http_modifier */
        if (pm != NULL) {
            if (pm->type == DETECT_CONTENT) {
                DetectContentData *tmp_cd = (DetectContentData *)pm->ctx;
                tmp_cd->flags &= ~DETECT_CONTENT_RELATIVE_NEXT;
            } else {
                DetectPcreData *tmp_pd = (DetectPcreData *)pm->ctx;
                tmp_pd->flags &= ~DETECT_PCRE_RELATIVE_NEXT;
            }
        } /* if (pm != NULL) */

        /* reassigning pm */
        pm = SigMatchGetLastSMFromLists(s, 2,
                                        DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_UMATCH]);
        if (pm == NULL) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "uricontent seen with a "
                       "distance or within without a previous http_uri "
                       "content.  Invalidating signature.");
            goto error;
        }
        DetectContentData *tmp_cd = (DetectContentData *)pm->ctx;
        tmp_cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
    }
    cd->id = DetectPatternGetId(de_ctx->mpm_pattern_id_store, cd, DETECT_SM_LIST_UMATCH);
    sm->type = DETECT_CONTENT;

    /* transfer the sm from the pmatch list to hcbdmatch list */
    SigMatchTransferSigMatchAcrossLists(sm,
                                        &s->sm_lists[DETECT_SM_LIST_PMATCH],
                                        &s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
                                        &s->sm_lists[DETECT_SM_LIST_UMATCH],
                                        &s->sm_lists_tail[DETECT_SM_LIST_UMATCH]);

    /* Flagged the signature as to inspect the app layer data */
    s->flags |= SIG_FLAG_APPLAYER;
    s->alproto = ALPROTO_HTTP;

    return 0;

error:
    return -1;
}


/******************************** UNITESTS **********************************/

#ifdef UNITTESTS

#include "stream-tcp-reassemble.h"

/**
 * \test Checks if a http_uri is registered in a Signature, if content is not
 *       specified in the signature
 */
int DetectHttpUriTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_uri\"; http_uri;sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a http_uri is registered in a Signature, if some parameter
 *       is specified with http_uri in the signature
 */
int DetectHttpUriTest02(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_uri\"; content:\"one\"; "
                               "http_cookie:wrong; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a http_uri is registered in a Signature
 */
int DetectHttpUriTest03(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_uri\"; content:\"one\"; "
                               "http_uri; content:\"two\"; http_uri; "
                               "content:\"three\"; http_uri; "
                               "sid:1;)");

    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH];
    if (sm == NULL) {
        printf("no sigmatch(es): ");
        goto end;
    }

    while (sm != NULL) {
        if (sm->type == DETECT_CONTENT) {
            result = 1;
        } else {
            printf("expected DETECT_AL_HTTP_URI, got %d: ", sm->type);
            goto end;
        }
        sm = sm->next;
    }

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a http_uri is registered in a Signature, when rawbytes is
 *       also specified in the signature
 */
int DetectHttpUriTest04(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_uri\"; content:\"one\"; "
                               "rawbytes; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a http_uri is successfully converted to a uricontent
 *
 */
int DetectHttpUriTest05(void)
{
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;
    int result = 0;

    if ((de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                    "(msg:\"Testing http_uri\"; "
                    "content:\"we are testing http_uri keyword\"; "
                    "http_uri; sid:1;)");
    if (s == NULL) {
        printf("sig failed to parse\n");
        goto end;
    }
    if (s->sm_lists[DETECT_SM_LIST_UMATCH] == NULL)
        goto end;
    if (s->sm_lists[DETECT_SM_LIST_UMATCH]->type != DETECT_CONTENT) {
        printf("wrong type\n");
        goto end;
    }

    char *str = "we are testing http_uri keyword";
    int uricomp = memcmp((const char *)((DetectContentData*) s->sm_lists[DETECT_SM_LIST_UMATCH]->ctx)->content, str, strlen(str)-1);
    int urilen = ((DetectContentData*) s->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx)->content_len;
    if (uricomp != 0 ||
        urilen != strlen("we are testing http_uri keyword")) {
        printf("sig failed to parse, content not setup properly\n");
        goto end;
    }
    result = 1;

end:
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) SigGroupCleanup(de_ctx);
    return result;
}

int DetectHttpUriTest06(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; content:\"one\"; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL\n");
        goto end;
    }

    DetectContentData *cd = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *ud = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx;
    if (cd->id == ud->id)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpUriTest07(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_uri; content:\"one\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL\n");
        goto end;
    }

    DetectContentData *cd = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *ud = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx;
    if (cd->id == ud->id)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpUriTest08(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; content:\"one\"; content:\"one\"; http_uri; content:\"one\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL\n");
        goto end;
    }

    DetectContentData *cd = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *ud = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx;
    if (cd->id != 0 || ud->id != 1)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpUriTest09(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_uri; content:\"one\"; content:\"one\"; content:\"one\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL\n");
        goto end;
    }

    DetectContentData *cd = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *ud = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx;
    if (cd->id != 1 || ud->id != 0)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpUriTest10(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_uri; "
                               "content:\"one\"; content:\"one\"; http_uri; content:\"one\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL\n");
        goto end;
    }

    DetectContentData *cd = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *ud1 = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx;
    DetectContentData *ud2 = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_UMATCH]->prev->ctx;
    if (cd->id != 1 || ud1->id != 0 || ud2->id != 0)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpUriTest11(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_uri; "
                               "content:\"one\"; content:\"one\"; http_uri; content:\"two\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL\n");
        goto end;
    }

    DetectContentData *cd = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *ud1 = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx;
    DetectContentData *ud2 = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_UMATCH]->prev->ctx;
    if (cd->id != 2 || ud1->id != 0 || ud2->id != 0)
        goto end;

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpUriTest12(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_uri; "
                               "content:\"two\"; distance:0; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL\n");
        goto end;
    }

    DetectContentData *ud1 = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_UMATCH]->prev->ctx;
    DetectContentData *ud2 = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx;
    if (ud1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(ud1->content, "one", ud1->content_len) != 0 ||
        ud2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(ud2->content, "two", ud1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpUriTest13(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_uri; "
                               "content:\"two\"; within:5; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL\n");
        goto end;
    }

    DetectContentData *ud1 = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_UMATCH]->prev->ctx;
    DetectContentData *ud2 = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx;
    if (ud1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(ud1->content, "one", ud1->content_len) != 0 ||
        ud2->flags != DETECT_CONTENT_WITHIN ||
        memcmp(ud2->content, "two", ud1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpUriTest14(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; within:5; http_uri; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        printf("de_ctx->sig_list != NULL\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpUriTest15(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_uri; within:5; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL\n");
        goto end;
    }

    DetectContentData *cd = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx;
    if (memcmp(cd->content, "one", cd->content_len) != 0 ||
        cd->flags != DETECT_CONTENT_WITHIN) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpUriTest16(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                                "(content:\"one\"; within:5; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        printf("de_ctx->sig_list != NULL\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpUriTest17(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(uricontent:\"one\"; "
                               "content:\"two\"; distance:0; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL\n");
        goto end;
    }

    DetectContentData *ud1 = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_UMATCH]->prev->ctx;
    DetectContentData *ud2 = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx;
    if (ud1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(ud1->content, "one", ud1->content_len) != 0 ||
        ud2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(ud2->content, "two", ud1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpUriTest18(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(uricontent:\"one\"; "
                               "content:\"two\"; within:5; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_UMATCH] == NULL\n");
        goto end;
    }

    DetectContentData *ud1 = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_UMATCH]->prev->ctx;
    DetectContentData *ud2 = de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_UMATCH]->ctx;
    if (ud1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(ud1->content, "one", ud1->content_len) != 0 ||
        ud2->flags != DETECT_CONTENT_WITHIN ||
        memcmp(ud2->content, "two", ud1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief   Register the UNITTESTS for the http_uri keyword
 */
void DetectHttpUriRegisterTests (void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectHttpUriTest01", DetectHttpUriTest01, 1);
    UtRegisterTest("DetectHttpUriTest02", DetectHttpUriTest02, 1);
    UtRegisterTest("DetectHttpUriTest03", DetectHttpUriTest03, 1);
    UtRegisterTest("DetectHttpUriTest04", DetectHttpUriTest04, 1);
    UtRegisterTest("DetectHttpUriTest05", DetectHttpUriTest05, 1);
    UtRegisterTest("DetectHttpUriTest06", DetectHttpUriTest06, 1);
    UtRegisterTest("DetectHttpUriTest07", DetectHttpUriTest07, 1);
    UtRegisterTest("DetectHttpUriTest08", DetectHttpUriTest08, 1);
    UtRegisterTest("DetectHttpUriTest09", DetectHttpUriTest09, 1);
    UtRegisterTest("DetectHttpUriTest10", DetectHttpUriTest10, 1);
    UtRegisterTest("DetectHttpUriTest11", DetectHttpUriTest11, 1);
    UtRegisterTest("DetectHttpUriTest12", DetectHttpUriTest12, 1);
    UtRegisterTest("DetectHttpUriTest13", DetectHttpUriTest13, 1);
    UtRegisterTest("DetectHttpUriTest14", DetectHttpUriTest14, 1);
    UtRegisterTest("DetectHttpUriTest15", DetectHttpUriTest15, 1);
    UtRegisterTest("DetectHttpUriTest16", DetectHttpUriTest16, 1);
    UtRegisterTest("DetectHttpUriTest17", DetectHttpUriTest17, 1);
    UtRegisterTest("DetectHttpUriTest18", DetectHttpUriTest18, 1);
#endif /* UNITTESTS */

}
/**
 * @}
 */
