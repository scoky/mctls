#include <limits.h>
#include <string.h>
#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

int spp_generate_slice_keys(SSL *s) {
    int i;    
    for (i = 0; i < s->slices_len; i++) {
        if (RAND_pseudo_bytes(&(s->slices[i].read_mat[0]), EVP_MAX_KEY_LENGTH) <= 0)
            return -1;
        if (RAND_pseudo_bytes(&(s->slices[i].write_mat[0]), EVP_MAX_KEY_LENGTH) <= 0)
            return -1;
    }
    return 1;
}

SPP_PROXY* spp_get_next_proxy(SSL *s, int forward) {
    int i;
    if (forward) {
        for (i = 0; i < s->proxies_len; i++) {
            if (s->proxies[i].done == 0) {
                return &(s->proxies[i]);
            }
        }
    } else {
        for (i = s->proxies_len - 1; i >= 0; i--) {
            if (s->proxies[i].done == 0) {
                return &(s->proxies[i]);
            }
        }
    }
    return NULL;
}

int spp_send_end_key_material(SSL *s) {
    unsigned char *p,*d;
    int n,i;
    unsigned long alg_k;
#ifndef OPENSSL_NO_ECDH
    EC_KEY *clnt_ecdh = NULL;
    const EC_POINT *srvr_ecpoint = NULL;
    EVP_PKEY *srvr_pub_pkey = NULL;
    unsigned char *encodedPoint = NULL;
    int encoded_pt_len = 0;
    BN_CTX * bn_ctx = NULL;
#endif
    struct sess_cert_st *sess_cert = NULL;

    if (s->state == SPP_ST_CW_PRXY_MAT_A) {
        d=(unsigned char *)s->init_buf->data;
        p= &(d[4]);

        alg_k=s->s3->tmp.new_cipher->algorithm_mkey;

        sess_cert = s->session->sess_cert;
        
        n = 0;
        for (i = 0; i < s->slices_len; i++) {
            *(p++) = s->slices[i].slice_id;
            s2n(EVP_MAX_KEY_LENGTH,p);    
            memcpy(p, s->slices[i].read_mat, EVP_MAX_KEY_LENGTH);
            p += EVP_MAX_KEY_LENGTH;
            s2n(EVP_MAX_KEY_LENGTH,p);    
            memcpy(p, s->slices[i].write_mat, EVP_MAX_KEY_LENGTH);
            p += EVP_MAX_KEY_LENGTH;
        }
        n = p-d-4;

        /* Fool emacs indentation */
        if (0) {}
#ifndef OPENSSL_NO_DH
        else if (alg_k & (SSL_kEDH|SSL_kDHr|SSL_kDHd)) {
            DH *dh_srvr,*dh_clnt;

            if (sess_cert == NULL)  {
                ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_UNEXPECTED_MESSAGE);
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,SSL_R_UNEXPECTED_MESSAGE);
                goto err;
            }

            if (sess_cert->peer_dh_tmp != NULL)
                dh_srvr=sess_cert->peer_dh_tmp;
            else {
                /* we get them from the cert */
                ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_HANDSHAKE_FAILURE);
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,SSL_R_UNABLE_TO_FIND_DH_PARAMETERS);
                goto err;
            }            
            
            /* TODO: encrypt with server public key */
            

        }
#endif

#ifndef OPENSSL_NO_ECDH 
        else if (alg_k & (SSL_kEECDH|SSL_kECDHr|SSL_kECDHe)) {
            const EC_GROUP *srvr_group = NULL;
            EC_KEY *tkey;
            int ecdh_clnt_cert = 0;
            int field_size = 0;

            if (sess_cert == NULL) {
                ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_UNEXPECTED_MESSAGE);
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,SSL_R_UNEXPECTED_MESSAGE);
                goto err;
            }

            if (s->session->sess_cert->peer_ecdh_tmp != NULL) {
                tkey = s->session->sess_cert->peer_ecdh_tmp;
            } else {
                /* Get the Server Public Key from Cert */
                srvr_pub_pkey = X509_get_pubkey(s->session-> \
                    sess_cert->peer_pkeys[SSL_PKEY_ECC].x509);
                if ((srvr_pub_pkey == NULL) ||
                    (srvr_pub_pkey->type != EVP_PKEY_EC) ||
                    (srvr_pub_pkey->pkey.ec == NULL)) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                        ERR_R_INTERNAL_ERROR);
                    goto err;
                }

                tkey = srvr_pub_pkey->pkey.ec;
            }

            srvr_group   = EC_KEY_get0_group(tkey);
            srvr_ecpoint = EC_KEY_get0_public_key(tkey);

            if ((srvr_group == NULL) || (srvr_ecpoint == NULL)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                    ERR_R_INTERNAL_ERROR);
                goto err;
            }

            /* use the 'p' output buffer for the ECDH key, but
             * make sure to clear it out afterwards
             */

            field_size = EC_GROUP_get_degree(srvr_group);
            if (field_size <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, 
                       ERR_R_ECDH_LIB);
                goto err;
            }
            n=ECDH_compute_key(p, (field_size+7)/8, srvr_ecpoint, clnt_ecdh, NULL);
            if (n <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, 
                       ERR_R_ECDH_LIB);
                goto err;
            }

            /* generate master key from the result */
            s->session->master_key_length = s->method->ssl3_enc \
                -> generate_master_secret(s, 
                    s->session->master_key,
                    p, n);

            memset(p, 0, n); /* clean up */

            if (ecdh_clnt_cert) {
                /* Send empty client key exch message */
                n = 0;
            } else {
                /* First check the size of encoding and
                 * allocate memory accordingly.
                 */
                encoded_pt_len = 
                    EC_POINT_point2oct(srvr_group, 
                        EC_KEY_get0_public_key(clnt_ecdh), 
                        POINT_CONVERSION_UNCOMPRESSED, 
                        NULL, 0, NULL);

                encodedPoint = (unsigned char *) 
                    OPENSSL_malloc(encoded_pt_len * 
                        sizeof(unsigned char)); 
                bn_ctx = BN_CTX_new();
                if ((encodedPoint == NULL) || (bn_ctx == NULL))  {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
                    goto err;
                }

                /* Encode the public key */
                n = EC_POINT_point2oct(srvr_group, 
                    EC_KEY_get0_public_key(clnt_ecdh), 
                    POINT_CONVERSION_UNCOMPRESSED, 
                    encodedPoint, encoded_pt_len, bn_ctx);

                *p = n; /* length of encoded point */
                /* Encoded point will be copied here */
                p += 1; 
                /* copy the point */
                memcpy((unsigned char *)p, encodedPoint, n);
                /* increment n to account for length field */
                n += 1; 
            }

            /* Free allocated memory */
            BN_CTX_free(bn_ctx);
            if (encodedPoint != NULL) OPENSSL_free(encodedPoint);
            if (clnt_ecdh != NULL) 
                     EC_KEY_free(clnt_ecdh);
            EVP_PKEY_free(srvr_pub_pkey);
        }
#endif /* !OPENSSL_NO_ECDH */
        else {
            ssl3_send_alert(s, SSL3_AL_FATAL,
                SSL_AD_HANDSHAKE_FAILURE);
            SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
                ERR_R_INTERNAL_ERROR);
            goto err;
        }

        *(d++)=SPP_MT_PROXY_KEY_MATERIAL;
        l2n3(n,d);

        s->state=SPP_ST_CW_PRXY_MAT_B;
        /* number of bytes to write */
        s->init_num=n+4;
        s->init_off=0;
    }

    /* SPP_ST_CW_PRXY_MAT_B */
    return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
err:
#ifndef OPENSSL_NO_ECDH
    BN_CTX_free(bn_ctx);
    if (encodedPoint != NULL) OPENSSL_free(encodedPoint);
    if (clnt_ecdh != NULL) 
            EC_KEY_free(clnt_ecdh);
    EVP_PKEY_free(srvr_pub_pkey);
#endif
    return(-1);
}

int spp_get_end_key_material(SSL *s) { 
    return -1;
}