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

                proxy = spp_get_next_proxy(s, 1);
                if (proxy == NULL) {
                    s->state=SSL3_ST_CW_KEY_EXCH_A;
                } else {
                    s->state=SPP_ST_CR_PRXY_CERT_A;
                }
                s->init_num=0;

                break;
                
            case SPP_ST_CR_PRXY_CERT_A:
            case SPP_ST_CR_PRXY_CERT_B:
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
                                
                proxy = spp_get_next_proxy(s, 1);
                if (proxy == NULL) {
                    s->state=SSL3_ST_CW_KEY_EXCH_A;
                } else {
                    /* Go back and read the next proxy */
                    s->state=SPP_ST_CR_PRXY_CERT_A;
                }
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
                    s->state = SPP_ST_CW_PRXY_MAT_A;
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
                    s->state = SPP_ST_CR_PRXY_MAT_A;
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
                
                // Store the values for end-to-end integrity checking
                if (spp_init_integrity_st(s) <= 0)
                    goto end;
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