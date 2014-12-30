#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

static const SSL_METHOD *spp_get_client_method(int ver);
static const SSL_METHOD *spp_get_client_method(int ver)
	{
	if (ver == SPP_VERSION)
		return SPP_client_method();
	return NULL;
	}

IMPLEMENT_spp_meth_func(SPP_VERSION, SPP_client_method,
			ssl_undefined_function,
			spp_connect,
			spp_get_client_method)

int spp_connect(SSL *s) {
    BUF_MEM *buf=NULL;
    SPP_PROXY* proxy;
    unsigned long Time=(unsigned long)time(NULL);
    void (*cb)(const SSL *ssl,int type,int val)=NULL;
    int ret= -1,i;
    int new_state,state,skip=0;

    RAND_add(&Time,sizeof(Time),0);
    ERR_clear_error();
    clear_sys_error();

    if (s->info_callback != NULL)
        cb=s->info_callback;
    else if (s->ctx->info_callback != NULL)
        cb=s->ctx->info_callback;

    s->in_handshake++;
    if (!SSL_in_init(s) || SSL_in_before(s)) SSL_clear(s); 

#ifndef OPENSSL_NO_HEARTBEATS
	/* If we're awaiting a HeartbeatResponse, pretend we
	 * already got and don't await it anymore, because
	 * Heartbeats don't make sense during handshakes anyway.
	 */
	if (s->tlsext_hb_pending) {
            s->tlsext_hb_pending = 0;
            s->tlsext_hb_seq++;
        }
#endif

    for (;;) {
        state=s->state;

        switch(s->state) {
            case SSL_ST_RENEGOTIATE:
                SSLerr(SSL_F_SSL3_CONNECT, ERR_R_INTERNAL_ERROR);
                ret = -1;
                goto end;
                
            case SSL_ST_BEFORE:
            case SSL_ST_CONNECT:
            case SSL_ST_BEFORE|SSL_ST_CONNECT:
            case SSL_ST_OK|SSL_ST_CONNECT:

                s->server=0; /* We are the client */
                s->proxy=0;
                s->proxy_id=1;
                
                if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_START,1);

                if ((s->version & 0xff00 ) != 0x0600) { /* SPP major version is 6 */
                    SSLerr(SSL_F_SSL3_CONNECT, ERR_R_INTERNAL_ERROR);
                    ret = -1;
                    goto end;
                }
				
                /* s->version=SSL3_VERSION; */
                s->type=SSL_ST_CONNECT;

                if (s->init_buf == NULL) {
                    if ((buf=BUF_MEM_new()) == NULL) {
                        ret= -1;
                        goto end;
                    }
                    if (!BUF_MEM_grow(buf,SSL3_RT_MAX_PLAIN_LENGTH)) {
                        ret= -1;
                        goto end;
                    }
                    s->init_buf=buf;
                    buf=NULL;
                }

                if (!ssl3_setup_buffers(s)) { ret= -1; goto end; }

                /* setup buffing BIO */
                if (!ssl_init_wbio_buffer(s,0)) { ret= -1; goto end; }

                /* don't push the buffering BIO quite yet */

                ssl3_init_finished_mac(s);

                s->state=SSL3_ST_CW_CLNT_HELLO_A;
                s->ctx->stats.sess_connect++;
                s->init_num=0;

                break;

            case SSL3_ST_CW_CLNT_HELLO_A:
            case SSL3_ST_CW_CLNT_HELLO_B:

                s->shutdown=0;
                ret=ssl3_client_hello(s);
                if (ret <= 0) goto end;
                s->state=SSL3_ST_CR_SRVR_HELLO_A;
                s->init_num=0;

                /* turn on buffering for the next lot of output */
                if (s->bbio != s->wbio)
                    s->wbio=BIO_push(s->bbio,s->wbio);

                break;                                

            case SSL3_ST_CR_SRVR_HELLO_A:
            case SSL3_ST_CR_SRVR_HELLO_B:
                ret=ssl3_get_server_hello(s);
		if (ret <= 0) goto end;

                s->state=SSL3_ST_CR_CERT_A;
                s->init_num=0;
                break;

            case SSL3_ST_CR_CERT_A:
            case SSL3_ST_CR_CERT_B:
                ret=ssl3_get_server_certificate(s);
                if (ret <= 0) goto end;
                s->state=SSL3_ST_CR_KEY_EXCH_A;
                s->init_num=0;
                break;

            case SSL3_ST_CR_KEY_EXCH_A:
            case SSL3_ST_CR_KEY_EXCH_B:
                ret=ssl3_get_key_exchange(s);
                if (ret <= 0) goto end;
                s->state=SSL3_ST_CR_CERT_REQ_A;
                s->init_num=0;

                /* at this point we check that we have the
                 * required stuff from the server */
                if (!ssl3_check_cert_and_algorithm(s)) {
                    ret= -1;
                    goto end;
                }
                break;                

            case SSL3_ST_CR_SRVR_DONE_A:
            case SSL3_ST_CR_SRVR_DONE_B:
                ret=ssl3_get_server_done(s);
                if (ret <= 0) goto end;
#ifndef OPENSSL_NO_SRP
                if (s->s3->tmp.new_cipher->algorithm_mkey & SSL_kSRP) {
                    if ((ret = SRP_Calc_A_param(s))<=0) {
                        SSLerr(SSL_F_SSL3_CONNECT,SSL_R_SRP_A_CALC);
                        ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_INTERNAL_ERROR);
                        goto end;
                    }
                }
#endif

                if (s->proxies_len > 0) {
                    s->state=SPP_ST_CR_PRXY_CERT_A;
                } else {
                    s->state=SSL3_ST_CW_KEY_EXCH_A;
                }
                s->init_num=0;

                break;
                
            case SPP_ST_CR_PRXY_CERT_A:
            case SPP_ST_CR_PRXY_CERT_B:
                proxy = spp_get_next_proxy(s, 1);
                if (proxy = NULL) {
                    s->state=SSL3_ST_CW_KEY_EXCH_A;
                    s->init_num=0;
                }
                ret=spp_get_proxy_certificate(s, proxy);
                if (ret <= 0) goto end;
                s->state=SSL3_ST_CR_KEY_EXCH_A;
                s->init_num=0;
                break;
                
            /* Receive the hello messages from the proxies now. */
            case SPP_ST_CR_PRXY_KEY_EXCH_A:
            case SPP_ST_CR_PRXY_KEY_EXCH_B:
                ret=spp_get_proxy_key_exchange(s, proxy);
                if (ret <= 0) goto end;
                s->state=SPP_ST_CR_PRXY_DONE_A;
                s->init_num=0; 
                break;
                
            case SPP_ST_CR_PRXY_DONE_A:
            case SPP_ST_CR_PRXY_DONE_B:
                ret=spp_get_proxy_done(s, proxy);
                if (ret <= 0) goto end;
                
                /* Go back and read the next proxy */
                s->state=SPP_ST_CR_PRXY_CERT_A;
                s->init_num=0;                
                break;
                
            case SSL3_ST_CW_KEY_EXCH_A:
            case SSL3_ST_CW_KEY_EXCH_B:
                ret=ssl3_send_client_key_exchange(s);
                if (ret <= 0) goto end;
                
                s->state=SPP_ST_CW_PRXY_MAT_A;
                s->s3->change_cipher_spec=0;
                s->init_num=0;
                break;

            /* Send the proxy key material. */
            case SPP_ST_CW_PRXY_MAT_A:
            case SPP_ST_CW_PRXY_MAT_B:
                for (i = 0; i < s->proxies_len; i++) {
                    ret=spp_send_proxy_key_material(s, &(s->proxies[i]));
                    if (ret <= 0) goto end;
                }
                ret=spp_send_end_key_material(s);
                
                s->state=SPP_ST_CR_PRXY_MAT_A;
                s->s3->change_cipher_spec=0;

                s->init_num=0;
                break;
                
            case SPP_ST_CR_PRXY_MAT_A:
            case SPP_ST_CR_PRXY_MAT_B:
                for (i = s->proxies_len-1; i >= 0; i--) {
                    ret=spp_get_proxy_key_material(s, &(s->proxies[i]));
                    if (ret <= 0) goto end;
                }
                ret=spp_get_end_key_material(s);
                if (ret <= 0) goto end;
                s->state=SSL3_ST_CW_CHANGE_A;
                s->s3->change_cipher_spec=0;

                s->init_num=0;
                break;

            case SSL3_ST_CW_CHANGE_A:
            case SSL3_ST_CW_CHANGE_B:
                ret=ssl3_send_change_cipher_spec(s,SSL3_ST_CW_CHANGE_A,SSL3_ST_CW_CHANGE_B);
                if (ret <= 0) goto end;

#if defined(OPENSSL_NO_TLSEXT) || defined(OPENSSL_NO_NEXTPROTONEG)
                s->state=SSL3_ST_CW_FINISHED_A;
#else
                if (s->s3->next_proto_neg_seen)
                    s->state=SSL3_ST_CW_NEXT_PROTO_A;
                else
                    s->state=SSL3_ST_CW_FINISHED_A;
#endif
                s->init_num=0;

                s->session->cipher=s->s3->tmp.new_cipher;
#ifdef OPENSSL_NO_COMP
                s->session->compress_meth=0;
#else
                if (s->s3->tmp.new_compression == NULL)
                    s->session->compress_meth=0;
                else
                    s->session->compress_meth= s->s3->tmp.new_compression->id;
#endif
                if (!s->method->ssl3_enc->setup_key_block(s)) {
                    ret= -1;
                    goto end;
                }

                if (!s->method->ssl3_enc->change_cipher_state(s,SSL3_CHANGE_CIPHER_CLIENT_WRITE)) {
                    ret= -1;
                    goto end;
                }
                /* Set up all */

                break;

#if !defined(OPENSSL_NO_TLSEXT) && !defined(OPENSSL_NO_NEXTPROTONEG)
            case SSL3_ST_CW_NEXT_PROTO_A:
            case SSL3_ST_CW_NEXT_PROTO_B:
                ret=ssl3_send_next_proto(s);
                if (ret <= 0) goto end;
                s->state=SSL3_ST_CW_FINISHED_A;
                break;
#endif

            case SSL3_ST_CW_FINISHED_A:
            case SSL3_ST_CW_FINISHED_B:
                ret=ssl3_send_finished(s,
                    SSL3_ST_CW_FINISHED_A,SSL3_ST_CW_FINISHED_B,
                    s->method->ssl3_enc->client_finished_label,
                    s->method->ssl3_enc->client_finished_label_len);
                if (ret <= 0) goto end;
                s->s3->flags |= SSL3_FLAGS_CCS_OK;
                s->state=SSL3_ST_CW_FLUSH;

                /* clear flags */
                s->s3->flags&= ~SSL3_FLAGS_POP_BUFFER;
                if (s->hit) {
                    s->s3->tmp.next_state=SSL_ST_OK;
                    if (s->s3->flags & SSL3_FLAGS_DELAY_CLIENT_FINISHED) {
                        s->state=SSL_ST_OK;
                        s->s3->flags|=SSL3_FLAGS_POP_BUFFER;
                        s->s3->delay_buf_pop_ret=0;
                    }
                } else {
#ifndef OPENSSL_NO_TLSEXT
                    /* Allow NewSessionTicket if ticket expected */
                    if (s->tlsext_ticket_expected)
                        s->s3->tmp.next_state=SSL3_ST_CR_SESSION_TICKET_A;
                    else
#endif
                        s->s3->tmp.next_state=SSL3_ST_CR_FINISHED_A;
                }
                s->init_num=0;
                break;

#ifndef OPENSSL_NO_TLSEXT
            case SSL3_ST_CR_SESSION_TICKET_A:
            case SSL3_ST_CR_SESSION_TICKET_B:
                ret=ssl3_get_new_session_ticket(s);
                if (ret <= 0) goto end;
                s->state=SSL3_ST_CR_FINISHED_A;
                s->init_num=0;
                break;

            case SSL3_ST_CR_CERT_STATUS_A:
            case SSL3_ST_CR_CERT_STATUS_B:
                ret=ssl3_get_cert_status(s);
                if (ret <= 0) goto end;
                s->state=SSL3_ST_CR_KEY_EXCH_A;
                s->init_num=0;
		break;
#endif

            case SSL3_ST_CR_FINISHED_A:
            case SSL3_ST_CR_FINISHED_B:
                s->s3->flags |= SSL3_FLAGS_CCS_OK;
                ret=ssl3_get_finished(s,SSL3_ST_CR_FINISHED_A,
                    SSL3_ST_CR_FINISHED_B);
                if (ret <= 0) goto end;

                if (s->hit)
                    s->state=SSL3_ST_CW_CHANGE_A;
                else
                    s->state=SSL_ST_OK;
                s->init_num=0;
                break;

            case SSL3_ST_CW_FLUSH:
                s->rwstate=SSL_WRITING;
                if (BIO_flush(s->wbio) <= 0) {
                    ret= -1;
                    goto end;
                }
                s->rwstate=SSL_NOTHING;
                s->state=s->s3->tmp.next_state;
                break;

            case SSL_ST_OK:
                /* clean a few things up */
                ssl3_cleanup_key_block(s);

                if (s->init_buf != NULL) {
                    BUF_MEM_free(s->init_buf);
                    s->init_buf=NULL;
                }

                /* If we are not 'joining' the last two packets,
                 * remove the buffering now */
                if (!(s->s3->flags & SSL3_FLAGS_POP_BUFFER))
                    ssl_free_wbio_buffer(s);
                /* else do it later in ssl3_write */

                s->init_num=0;
                s->renegotiate=0;
                s->new_session=0;

                ssl_update_cache(s,SSL_SESS_CACHE_CLIENT);
                if (s->hit) s->ctx->stats.sess_hit++;

                ret=1;
                /* s->server=0; */
                s->handshake_func=ssl3_connect;
                s->ctx->stats.sess_connect_good++;

                if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_DONE,1);

                goto end;
                /* break; */
			
            default:
                SSLerr(SSL_F_SSL3_CONNECT,SSL_R_UNKNOWN_STATE);
                ret= -1;
                goto end;
                /* break; */
        }

        /* did we do anything */
        if (!s->s3->tmp.reuse_message && !skip) {
            if (s->debug) {
                if ((ret=BIO_flush(s->wbio)) <= 0)
                    goto end;
            }

            if ((cb != NULL) && (s->state != state)) {
                new_state=s->state;
                s->state=state;
                cb(s,SSL_CB_CONNECT_LOOP,1);
                s->state=new_state;
            }
        }
        skip=0;
    }
end:
    s->in_handshake--;
    if (buf != NULL)
        BUF_MEM_free(buf);
    if (cb != NULL)
        cb(s,SSL_CB_CONNECT_EXIT,ret);
    return(ret);
}
        
int spp_get_proxy_key_material(SSL *s, SPP_PROXY* proxy) { 
    return -1;
}

int spp_send_proxy_key_material(SSL *s, SPP_PROXY* proxy) {
    unsigned char *p,*d;
    int n;
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

            

            /* use the 'p' output buffer for the DH key, but
             * make sure to clear it out afterwards */

            n=DH_compute_key(p,dh_srvr->pub_key,dh_clnt);

            if (n <= 0) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_DH_LIB);
                DH_free(dh_clnt);
                goto err;
            }

            /* generate master key from the result */
            s->session->master_key_length=
                s->method->ssl3_enc->generate_master_secret(s,
                    s->session->master_key,p,n);
            /* clean up */
            memset(p,0,n);

            /* send off the data */
            n=BN_num_bytes(dh_clnt->pub_key);
            s2n(n,p);
            BN_bn2bin(dh_clnt->pub_key,p);
            n+=2;

            DH_free(dh_clnt);
        }
#endif

#ifndef OPENSSL_NO_ECDH 
        else if (alg_k & (SSL_kEECDH|SSL_kECDHr|SSL_kECDHe)) {
            const EC_GROUP *srvr_group = NULL;
            EC_KEY *tkey;
            int ecdh_clnt_cert = 0;
            int field_size = 0;

            if (s->session->sess_cert == NULL)  {
                ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_UNEXPECTED_MESSAGE);
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,SSL_R_UNEXPECTED_MESSAGE);
                goto err;
            }

            /* Did we send out the client's
             * ECDH share for use in premaster
             * computation as part of client certificate?
             * If so, set ecdh_clnt_cert to 1.
             */
            if ((alg_k & (SSL_kECDHr|SSL_kECDHe)) && (s->cert != NULL)) {
                /* XXX: For now, we do not support client
                 * authentication using ECDH certificates.
                 * To add such support, one needs to add
                 * code that checks for appropriate 
                 * conditions and sets ecdh_clnt_cert to 1.
                 * For example, the cert have an ECC
                 * key on the same curve as the server's
                 * and the key should be authorized for
                 * key agreement.
                 *
                 * One also needs to add code in ssl3_connect
                 * to skip sending the certificate verify
                 * message.
                 *
                 * if ((s->cert->key->privatekey != NULL) &&
                 *     (s->cert->key->privatekey->type ==
                 *      EVP_PKEY_EC) && ...)
                 * ecdh_clnt_cert = 1;
                 */
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

            if ((clnt_ecdh=EC_KEY_new()) == NULL) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
                goto err;
            }

            if (!EC_KEY_set_group(clnt_ecdh, srvr_group)) {
                SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_EC_LIB);
                goto err;
            }
            if (ecdh_clnt_cert) { 
                /* Reuse key info from our certificate
                 * We only need our private key to perform
                 * the ECDH computation.
                 */
                const BIGNUM *priv_key;
                tkey = s->cert->key->privatekey->pkey.ec;
                priv_key = EC_KEY_get0_private_key(tkey);
                if (priv_key == NULL) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
                    goto err;
                }
                if (!EC_KEY_set_private_key(clnt_ecdh, priv_key)) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_EC_LIB);
                    goto err;
                }
            } else {
                /* Generate a new ECDH key pair */
                if (!(EC_KEY_generate_key(clnt_ecdh))) {
                    SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_ECDH_LIB);
                    goto err;
                }
                        }

                /* use the 'p' output buffer for the ECDH key, but
                 * make sure to clear it out afterwards
                 */

                field_size = EC_GROUP_get_degree(srvr_group);
                if (field_size <= 0)
                        {
                        SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, 
                               ERR_R_ECDH_LIB);
                        goto err;
                        }
                n=ECDH_compute_key(p, (field_size+7)/8, srvr_ecpoint, clnt_ecdh, NULL);
                if (n <= 0)
                        {
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

                if (ecdh_clnt_cert) 
                        {
                        /* Send empty client key exch message */
                        n = 0;
                        }
                else 
                        {
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
                        if ((encodedPoint == NULL) || 
                            (bn_ctx == NULL)) 
                                {
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