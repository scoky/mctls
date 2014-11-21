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
    // Error if a slice has not been specified for this encrypt/decrypt op
    if (!s->cur_slice) {
        SSLerr(SSL_F_SPP_ENC,SPP_R_MISSING_SLICE);
        return -1;
    }
    
    /* If we do not possess the encryption material for this slice, 
     * do not attempt to decrypt. */
    if (!s->cur_slice->have_material) {
        return 0;
    }
    
    /* Pick the right slice, and encrypt with it. */
    if (send) {
        s->enc_write_ctx = s->cur_slice->enc_write_ctx;
    } else if (!send) {
        s->enc_read_ctx = s->cur_slice->enc_read_ctx;
    }
    return tls1_enc(s, send);
}

/* TODO: If MAC needs to be passed all the way, must reimplement MAC function 
 * as well. */