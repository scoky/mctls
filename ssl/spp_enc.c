#include <stdio.h>
#include "ssl_locl.h"
#ifndef OPENSSL_NO_COMP
#include <openssl/comp.h>
#endif
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#ifdef KSSL_DEBUG
#include <openssl/des.h>
#endif

int spp_enc(SSL *s, int send) {
    /* Pick the right slice, and encrypt with it. */
    if (s->cur_slice) {
        s->enc_write_ctx = s->cur_slice->enc_write_ctx;
        s->enc_read_ctx = s->cur_slice->enc_read_ctx;
    }
    return tls1_enc(s, send);
}
