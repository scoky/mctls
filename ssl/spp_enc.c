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
    SPP_SLICE *slice;
    
    if (send) {
        slice = s->write_slice;
    } else {
        slice = s->read_slice;
    }
    // Error if a slice has not been specified for this encrypt/decrypt op
    if (slice == NULL) {
        SSLerr(SSL_F_SPP_ENC,SPP_R_MISSING_SLICE);
        return -1;
    }
    
    /* If we do not possess the encryption material for this slice, 
     * do not attempt to decrypt. Not Needed, see below. */
    //if (!slice->have_material) {
        /* Copy the still encrypted content to the correct location. */
    //    return 1;
    //}
    
    /* Pick the right slice, and encrypt with it. */
    /* If we do not have the encryption material, slice->enc_XXX_ctx should be null. 
     * In that case, tls1 applies the null cipher. */
    if (send) {
        s->enc_write_ctx = slice->enc_write_ctx;
    } else if (!send) {
        s->enc_read_ctx = slice->enc_read_ctx;
    }
    return tls1_enc(s, send);
}