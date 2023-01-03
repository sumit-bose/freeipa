/*
 * FreeIPA 2FA companion daemon
 *
 * Authors: Sumit Bose <sbose@redhat.com>
 *
 * Copyright (C) 2022  Sumit Bose, Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This file contains various helper functions for the passkey feature.
 */

#define _GNU_SOURCE /* for asprintf() */
#include <stdio.h>
#include <jansson.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include "internal.h"

struct passkey_data {
    int phase;
    char *state;
    union {
        struct passkey_challenge {
            char *domain;
            char **credential_id_list;
            int user_verification;
            char *cryptographic_challenge;
        } challenge;

        struct sss_passkey_reply {
            char *credential_id;
            char *cryptographic_challenge;
            char *authenticator_data;
            char *assertion_signature;
        } response;
    } data;
    json_t *jdata;
    json_t *jroot;
};

struct otpd_queue_item_passkey {
    char *domain;
    char *ipaRequireUserVerification;
    struct passkey_data *data_in;
    struct passkey_data *data_out;
    krb5_data state;
};

void free_otpd_queue_item_passkey(struct otpd_queue_item *item)
{
    free(item->passkey->domain);
    free(item->passkey->ipaRequireUserVerification);

    if (item->passkey->data_in != NULL) {
        json_decref(item->passkey->data_in->jdata);
        json_decref(item->passkey->data_in->jroot);
        free(item->passkey->data_in);
    }

    if (item->passkey->data_out != NULL) {
        json_decref(item->passkey->data_out->jdata);
        json_decref(item->passkey->data_out->jroot);
        free(item->passkey->data_out);
    }

    free(item->passkey);
}

static struct otpd_queue_item_passkey *get_otpd_queue_item_passkey(void)
{
    struct otpd_queue_item_passkey *p;

    p = calloc(1, sizeof(struct otpd_queue_item_passkey));
    if (p == NULL) {
        return NULL;
    }

    p->data_in = calloc(1, sizeof(struct passkey_data));
    if (p->data_in == NULL) {
        free(p);
        return NULL;
    }

    p->data_out = calloc(1, sizeof(struct passkey_data));
    if (p->data_out == NULL) {
        free(p->data_in);
        free(p);
        return NULL;
    }

    p->data_in->phase = -1;
    p->data_out->phase = -1;

    return p;
}

/* Parse the passkey configuration */
const char *otpd_parse_passkey(LDAP *ldp, LDAPMessage *entry,
                               struct otpd_queue_item *item)
{
    int i;

    if (item->passkey == NULL) {
        item->passkey = calloc(1, sizeof(struct otpd_queue_item_passkey));
        if (item->passkey == NULL) {
            return strerror(ENOMEM);
        }
    }

    i = get_string(ldp, entry, "ipaRequireUserVerification",
                   &item->passkey->ipaRequireUserVerification);
    if ((i != 0) && (i != ENOENT)) {
        return strerror(i);
    }

    return NULL;
}

static int decode_json(const char *inp, size_t size, struct passkey_data *data)
{
    json_error_t jret;
    int ret;

    data->jroot = json_loadb(inp, size, 0, &jret);
    if (data->jroot == NULL) {
        return EINVAL;
    }
    data->jdata = NULL;
    data->phase = -1;

    ret = json_unpack(data->jroot, "{s:i, s?:s, s?:o}",
                     "phase", &data->phase,
                     "state", &data->state,
                     "data", &data->jdata);
    if (ret != 0) {
        ret = EINVAL;
        goto done;
    }

    switch (data->phase) {
    case 0: /* SSS_PASSKEY_PHASE_INIT */
        /* no data */
        if (data->jdata != NULL) {
            ret = EINVAL;
        } else {
            ret = 0;
        }
        break;
    case 2: /* SSS_PASSKEY_PHASE_REPLY */
        ret = json_unpack(data->jdata, "{s:s, s:s, s:s, s:s}",
                "credential_id", &data->data.response.credential_id,
                "cryptographic_challenge", &data->data.response.cryptographic_challenge,
                "authenticator_data", &data->data.response.authenticator_data,
                "assertion_signature", &data->data.response.assertion_signature);
    default:
        ret = EINVAL;
    }

done:
    if (ret != 0) {
        json_decref(data->jdata);
        json_decref(data->jroot);
    }

    return ret;
}

int passkey_parse_data(const char *data, size_t size, struct otpd_queue_item *item)
{
    item->passkey = get_otpd_queue_item_passkey();
    if (item->passkey == NULL) {
        return ENOMEM;
    }

    return decode_json(data, size, item->passkey->data_in);
}

static json_t *ipa_passkey_to_json_array(char **ipa_passkey)
{
    int ret;
    const char *sep;
    size_t c;
    json_t *ja = NULL;
    json_t *js;

    if (ipa_passkey == NULL || *ipa_passkey == NULL) {
        return NULL;
    }

    ja = json_array();
    if (ja == NULL) {
        return NULL;
    }

    for (c = 0; ipa_passkey[c] != NULL; c++) {
        sep = strchr(ipa_passkey[c], ',');
        if (sep == NULL || sep == ipa_passkey[c]) {
            ret = EINVAL;
            goto done;
        }

        js = json_stringn(ipa_passkey[c], sep - ipa_passkey[c]);
        if (js == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = json_array_append_new(ja, js);
        if (ret != 0) {
            goto done;
        }
    }

done:
    if (ret != 0) {
        json_decref(ja);
        return NULL;
    }

    return ja;
}

#define CHALLENGE_LENGTH 32
static unsigned char *get_b64_challenge(void)
{
    int ret;
    unsigned char buf[CHALLENGE_LENGTH];
    unsigned char *b64;

    ret = RAND_bytes(buf, CHALLENGE_LENGTH);
    if (ret != 1) {
        return NULL;
    }

    b64 = calloc(1, 2 * CHALLENGE_LENGTH);
    if (b64 == NULL) {
        return NULL;
    }

    ret = EVP_EncodeBlock(b64, buf, CHALLENGE_LENGTH);
    if (ret == 0) {
        free(b64);
        return NULL;
    }

    return b64;
}

static int prepare_rad_reply(struct otpd_queue_item *item)
{
    krad_attrset *attrset = NULL;
    int ret;
    json_t *jtmp = NULL;
    char *stmp = NULL;
    struct otpd_queue_item *state_item = NULL;

    ret = otpd_queue_item_new(NULL, &state_item);
    if (ret != 0) {
        otpd_log_req(item->req, "Failed to allocate state item");
        goto done;
    }

    ret = krad_attrset_new(ctx.kctx, &attrset);
    if (ret != 0) {
        otpd_log_req(item->req, "Failed to create radius attribute set");
        goto done;
    }

    state_item->passkey->state.magic = 0;

    jtmp = json_pack("{s:i, s:s, s:o}", item->passkey->data_out->phase,
                                        item->passkey->data_out->state,
                                        item->passkey->data_out->jdata);
    if (jtmp == NULL) {
        otpd_log_req(item->req, "Failed to pack json reply");
        ret = EIO;
        goto done;
    }

    stmp = json_dumps(jtmp, JSON_COMPACT);
    if (stmp == NULL) {
        otpd_log_req(item->req, "json_dumps() failed");
        ret = EIO;
        goto done;
    }

    ret = asprintf(&(state_item->passkey->state.data), "passkey %s", stmp);
    if (ret < 0) {
        otpd_log_req(item->req, "asprintf() failed");
        ret = ENOMEM;
        goto done;
    }
    state_item->passkey->state.length = strlen(state_item->passkey->state.data);

    ret = add_krad_attr_to_set(item->req, attrset, &(state_item->passkey->state),
                               krad_attr_name2num("Proxy-State"),
                               "Failed to serialize state to attribute set");
    if (ret != 0) {
        goto done;
    }

    ret = krad_packet_new_response(ctx.kctx, SECRET,
                                   krad_code_name2num("Access-Challenge"),
                                   attrset,
                                   item->req, &item->rsp);
    if (ret != 0) {
        otpd_log_err(ret, "Failed to create radius response");
        item->rsp = NULL;
    }

    otpd_queue_push(&ctx.oauth2_state.states, state_item);

    ret = 0;

done:
    krad_attrset_free(attrset);
    free(stmp);
    json_decref(jtmp);

    if (ret != 0) {
        if (state_item != NULL) {
            free(state_item->oauth2.state.data);
            free(state_item->oauth2.device_code_reply);
            free(state_item);
        }
    }

    return ret;
}

static int do_passkey_challenge(struct otpd_queue_item *item)
{
    json_t *cred_id_list;
    int user_verification = 1;
    unsigned char *challenge = NULL;
    int ret;

    cred_id_list = ipa_passkey_to_json_array(item->user.ipaPassKey);
    if (cred_id_list == NULL) {
        return EINVAL;
    }

    if (item->passkey->ipaRequireUserVerification == NULL || 
            strcasecmp(item->passkey->ipaRequireUserVerification, "default") == 0) {
        user_verification = -1;
    } else if (strcasecmp(item->passkey->ipaRequireUserVerification, "off") == 0) {
        user_verification = 0;
    }

    challenge = get_b64_challenge();
    if (challenge == NULL) {
        ret = ENOMEM;
        goto done;
    }

    item->passkey->data_out->jdata = json_pack("{s:s, s:o, s:i, s:s}",
                                       "domain", item->passkey->domain,
                                       "credential_id_list", cred_id_list,
                                       "user_verification", user_verification,
                                       "cryptographic_challenge", challenge);
    if (item->passkey->data_out->jdata == NULL) {
        ret = EIO;
        goto done;
    }
                    
    item->passkey->data_out->phase = 1; /* SSS_PASSKEY_PHASE_CHALLENGE */
    item->passkey->data_out->state = "STATE";

    ret = prepare_rad_reply(item);
    if (ret != 0) {
        otpd_log_err(ret, "prepare_rad_reply() failed.");
        goto done;
    }

    ret = 0; 
done:
    free(challenge);    

    otpd_queue_push(&ctx.stdio.responses, item);
    verto_set_flags(ctx.stdio.writer, VERTO_EV_FLAG_PERSIST |
                                      VERTO_EV_FLAG_IO_ERROR |
                                      VERTO_EV_FLAG_IO_READ |
                                      VERTO_EV_FLAG_IO_WRITE);

    return ret;
}

static int do_passkey_response(struct otpd_queue_item *item)
{
    return ENOTSUP;
}

int do_passkey(struct otpd_queue_item *item)
{
    if (item == NULL || item->passkey == NULL
            || item->passkey->data_in == NULL) {
        return EINVAL;
    }

    switch (item->passkey->data_in->phase) {
    case 0: /* SSS_PASSKEY_PHASE_INIT */
        return do_passkey_challenge(item);
    case 2: /* SSS_PASSKEY_PHASE_REPLY */
        return do_passkey_response(item);
    default:
        return EINVAL;
    }

}
