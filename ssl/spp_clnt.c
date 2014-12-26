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
    unsigned long Time=(unsigned long)time(NULL);
    void (*cb)(const SSL *ssl,int type,int val)=NULL;
    int ret= -1;
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
                ret=spp_get_proxy_certificate(s);
                if (ret <= 0) goto end;
                s->state=SSL3_ST_CR_KEY_EXCH_A;
                s->init_num=0;
                break;
                
            /* Receive the hello messages from the proxies now. */
            case SPP_ST_CR_PRXY_KEY_EXCH_A:
            case SPP_ST_CR_PRXY_KEY_EXCH_B:
                ret=spp_get_proxy_key_exchange(s);
                if (ret <= 0) goto end;
                s->state=SPP_ST_CR_PRXY_DONE_A;
                s->init_num=0; 
                break;
                
            case SPP_ST_CR_PRXY_DONE_A:
            case SPP_ST_CR_PRXY_DONE_B:
                ret=spp_get_proxy_done(s);
                if (ret <= 0) goto end;
                
                /* If received from all proxies, go to key_exchange state.
                 * Else, loop again. */
                if (s->proxies_complete) {
                    s->state=SSL3_ST_CW_KEY_EXCH_A;
                } else {
                    s->state=SPP_ST_CR_PRXY_CERT_A;
                }
                s->init_num=0;                
                break;
                
            case SSL3_ST_CW_KEY_EXCH_A:
            case SSL3_ST_CW_KEY_EXCH_B:
                ret=ssl3_send_client_key_exchange(s);
                if (ret <= 0) goto end;
                
                s->state=SSL3_ST_CW_CHANGE_A;
                s->s3->change_cipher_spec=0;
                s->init_num=0;
                break;

            /* Send the proxy key material. */
            case SPP_ST_CW_PRXY_MAT_A:
            case SPP_ST_CW_PRXY_MAT_B:
                ret=spp_send_proxy_key_material(s);
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
        
int spp_send_proxy_key_material(SSL *s) {
	unsigned char *p,*d;
	int n;
	unsigned long alg_k;
#ifndef OPENSSL_NO_RSA
	unsigned char *q;
	EVP_PKEY *pkey=NULL;
#endif
#ifndef OPENSSL_NO_ECDH
	EC_KEY *clnt_ecdh = NULL;
	const EC_POINT *srvr_ecpoint = NULL;
	EVP_PKEY *srvr_pub_pkey = NULL;
	unsigned char *encodedPoint = NULL;
	int encoded_pt_len = 0;
	BN_CTX * bn_ctx = NULL;
#endif

	if (s->state == SSL3_ST_CW_KEY_EXCH_A)
		{
		d=(unsigned char *)s->init_buf->data;
		p= &(d[4]);

		alg_k=s->s3->tmp.new_cipher->algorithm_mkey;

		/* Fool emacs indentation */
		if (0) {}
#ifndef OPENSSL_NO_RSA
		else if (alg_k & SSL_kRSA)
			{
			RSA *rsa;
			unsigned char tmp_buf[SSL_MAX_MASTER_KEY_LENGTH];

			if (s->session->sess_cert == NULL)
				{
				/* We should always have a server certificate with SSL_kRSA. */
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_INTERNAL_ERROR);
				goto err;
				}

			if (s->session->sess_cert->peer_rsa_tmp != NULL)
				rsa=s->session->sess_cert->peer_rsa_tmp;
			else
				{
				pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
				if ((pkey == NULL) ||
					(pkey->type != EVP_PKEY_RSA) ||
					(pkey->pkey.rsa == NULL))
					{
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_INTERNAL_ERROR);
					goto err;
					}
				rsa=pkey->pkey.rsa;
				EVP_PKEY_free(pkey);
				}
				
			tmp_buf[0]=s->client_version>>8;
			tmp_buf[1]=s->client_version&0xff;
			if (RAND_bytes(&(tmp_buf[2]),sizeof tmp_buf-2) <= 0)
					goto err;

			s->session->master_key_length=sizeof tmp_buf;

			q=p;
			/* Fix buf for TLS and beyond */
			if (s->version > SSL3_VERSION)
				p+=2;
			n=RSA_public_encrypt(sizeof tmp_buf,
				tmp_buf,p,rsa,RSA_PKCS1_PADDING);
#ifdef PKCS1_CHECK
			if (s->options & SSL_OP_PKCS1_CHECK_1) p[1]++;
			if (s->options & SSL_OP_PKCS1_CHECK_2) tmp_buf[0]=0x70;
#endif
			if (n <= 0)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,SSL_R_BAD_RSA_ENCRYPT);
				goto err;
				}

			/* Fix buf for TLS and beyond */
			if (s->version > SSL3_VERSION)
				{
				s2n(n,q);
				n+=2;
				}

			s->session->master_key_length=
				s->method->ssl3_enc->generate_master_secret(s,
					s->session->master_key,
					tmp_buf,sizeof tmp_buf);
			OPENSSL_cleanse(tmp_buf,sizeof tmp_buf);
			}
#endif
#ifndef OPENSSL_NO_KRB5
		else if (alg_k & SSL_kKRB5)
			{
			krb5_error_code	krb5rc;
			KSSL_CTX	*kssl_ctx = s->kssl_ctx;
			/*  krb5_data	krb5_ap_req;  */
			krb5_data	*enc_ticket;
			krb5_data	authenticator, *authp = NULL;
			EVP_CIPHER_CTX	ciph_ctx;
			const EVP_CIPHER *enc = NULL;
			unsigned char	iv[EVP_MAX_IV_LENGTH];
			unsigned char	tmp_buf[SSL_MAX_MASTER_KEY_LENGTH];
			unsigned char	epms[SSL_MAX_MASTER_KEY_LENGTH 
						+ EVP_MAX_IV_LENGTH];
			int 		padl, outl = sizeof(epms);

			EVP_CIPHER_CTX_init(&ciph_ctx);

#ifdef KSSL_DEBUG
			printf("ssl3_send_client_key_exchange(%lx & %lx)\n",
				alg_k, SSL_kKRB5);
#endif	/* KSSL_DEBUG */

			authp = NULL;
#ifdef KRB5SENDAUTH
			if (KRB5SENDAUTH)  authp = &authenticator;
#endif	/* KRB5SENDAUTH */

			krb5rc = kssl_cget_tkt(kssl_ctx, &enc_ticket, authp,
				&kssl_err);
			enc = kssl_map_enc(kssl_ctx->enctype);
			if (enc == NULL)
			    goto err;
#ifdef KSSL_DEBUG
			{
			printf("kssl_cget_tkt rtn %d\n", krb5rc);
			if (krb5rc && kssl_err.text)
			  printf("kssl_cget_tkt kssl_err=%s\n", kssl_err.text);
			}
#endif	/* KSSL_DEBUG */

			if (krb5rc)
				{
				ssl3_send_alert(s,SSL3_AL_FATAL,
						SSL_AD_HANDSHAKE_FAILURE);
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
						kssl_err.reason);
				goto err;
				}

			/*  20010406 VRS - Earlier versions used KRB5 AP_REQ
			**  in place of RFC 2712 KerberosWrapper, as in:
			**
			**  Send ticket (copy to *p, set n = length)
			**  n = krb5_ap_req.length;
			**  memcpy(p, krb5_ap_req.data, krb5_ap_req.length);
			**  if (krb5_ap_req.data)  
			**    kssl_krb5_free_data_contents(NULL,&krb5_ap_req);
			**
			**  Now using real RFC 2712 KerberosWrapper
			**  (Thanks to Simon Wilkinson <sxw@sxw.org.uk>)
			**  Note: 2712 "opaque" types are here replaced
			**  with a 2-byte length followed by the value.
			**  Example:
			**  KerberosWrapper= xx xx asn1ticket 0 0 xx xx encpms
			**  Where "xx xx" = length bytes.  Shown here with
			**  optional authenticator omitted.
			*/

			/*  KerberosWrapper.Ticket		*/
			s2n(enc_ticket->length,p);
			memcpy(p, enc_ticket->data, enc_ticket->length);
			p+= enc_ticket->length;
			n = enc_ticket->length + 2;

			/*  KerberosWrapper.Authenticator	*/
			if (authp  &&  authp->length)  
				{
				s2n(authp->length,p);
				memcpy(p, authp->data, authp->length);
				p+= authp->length;
				n+= authp->length + 2;
				
				free(authp->data);
				authp->data = NULL;
				authp->length = 0;
				}
			else
				{
				s2n(0,p);/*  null authenticator length	*/
				n+=2;
				}
 
			    tmp_buf[0]=s->client_version>>8;
			    tmp_buf[1]=s->client_version&0xff;
			    if (RAND_bytes(&(tmp_buf[2]),sizeof tmp_buf-2) <= 0)
				goto err;

			/*  20010420 VRS.  Tried it this way; failed.
			**	EVP_EncryptInit_ex(&ciph_ctx,enc, NULL,NULL);
			**	EVP_CIPHER_CTX_set_key_length(&ciph_ctx,
			**				kssl_ctx->length);
			**	EVP_EncryptInit_ex(&ciph_ctx,NULL, key,iv);
			*/

			memset(iv, 0, sizeof iv);  /* per RFC 1510 */
			EVP_EncryptInit_ex(&ciph_ctx,enc, NULL,
				kssl_ctx->key,iv);
			EVP_EncryptUpdate(&ciph_ctx,epms,&outl,tmp_buf,
				sizeof tmp_buf);
			EVP_EncryptFinal_ex(&ciph_ctx,&(epms[outl]),&padl);
			outl += padl;
			if (outl > (int)sizeof epms)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
				goto err;
				}
			EVP_CIPHER_CTX_cleanup(&ciph_ctx);

			/*  KerberosWrapper.EncryptedPreMasterSecret	*/
			s2n(outl,p);
			memcpy(p, epms, outl);
			p+=outl;
			n+=outl + 2;

			s->session->master_key_length=
				s->method->ssl3_enc->generate_master_secret(s,
					s->session->master_key,
					tmp_buf, sizeof tmp_buf);

			OPENSSL_cleanse(tmp_buf, sizeof tmp_buf);
			OPENSSL_cleanse(epms, outl);
			}
#endif
#ifndef OPENSSL_NO_DH
		else if (alg_k & (SSL_kEDH|SSL_kDHr|SSL_kDHd))
			{
			DH *dh_srvr,*dh_clnt;

			if (s->session->sess_cert == NULL) 
				{
				ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_UNEXPECTED_MESSAGE);
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,SSL_R_UNEXPECTED_MESSAGE);
				goto err;
				}

			if (s->session->sess_cert->peer_dh_tmp != NULL)
				dh_srvr=s->session->sess_cert->peer_dh_tmp;
			else
				{
				/* we get them from the cert */
				ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_HANDSHAKE_FAILURE);
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,SSL_R_UNABLE_TO_FIND_DH_PARAMETERS);
				goto err;
				}
			
			/* generate a new random key */
			if ((dh_clnt=DHparams_dup(dh_srvr)) == NULL)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_DH_LIB);
				goto err;
				}
			if (!DH_generate_key(dh_clnt))
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_DH_LIB);
				DH_free(dh_clnt);
				goto err;
				}

			/* use the 'p' output buffer for the DH key, but
			 * make sure to clear it out afterwards */

			n=DH_compute_key(p,dh_srvr->pub_key,dh_clnt);

			if (n <= 0)
				{
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

			/* perhaps clean things up a bit EAY EAY EAY EAY*/
			}
#endif

#ifndef OPENSSL_NO_ECDH 
		else if (alg_k & (SSL_kEECDH|SSL_kECDHr|SSL_kECDHe))
			{
			const EC_GROUP *srvr_group = NULL;
			EC_KEY *tkey;
			int ecdh_clnt_cert = 0;
			int field_size = 0;

			if (s->session->sess_cert == NULL) 
				{
				ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_UNEXPECTED_MESSAGE);
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,SSL_R_UNEXPECTED_MESSAGE);
				goto err;
				}

			/* Did we send out the client's
			 * ECDH share for use in premaster
			 * computation as part of client certificate?
			 * If so, set ecdh_clnt_cert to 1.
			 */
			if ((alg_k & (SSL_kECDHr|SSL_kECDHe)) && (s->cert != NULL)) 
				{
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

			if (s->session->sess_cert->peer_ecdh_tmp != NULL)
				{
				tkey = s->session->sess_cert->peer_ecdh_tmp;
				}
			else
				{
				/* Get the Server Public Key from Cert */
				srvr_pub_pkey = X509_get_pubkey(s->session-> \
				    sess_cert->peer_pkeys[SSL_PKEY_ECC].x509);
				if ((srvr_pub_pkey == NULL) ||
				    (srvr_pub_pkey->type != EVP_PKEY_EC) ||
				    (srvr_pub_pkey->pkey.ec == NULL))
					{
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
					    ERR_R_INTERNAL_ERROR);
					goto err;
					}

				tkey = srvr_pub_pkey->pkey.ec;
				}

			srvr_group   = EC_KEY_get0_group(tkey);
			srvr_ecpoint = EC_KEY_get0_public_key(tkey);

			if ((srvr_group == NULL) || (srvr_ecpoint == NULL))
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
				    ERR_R_INTERNAL_ERROR);
				goto err;
				}

			if ((clnt_ecdh=EC_KEY_new()) == NULL) 
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
				goto err;
				}

			if (!EC_KEY_set_group(clnt_ecdh, srvr_group))
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_EC_LIB);
				goto err;
				}
			if (ecdh_clnt_cert) 
				{ 
				/* Reuse key info from our certificate
				 * We only need our private key to perform
				 * the ECDH computation.
				 */
				const BIGNUM *priv_key;
				tkey = s->cert->key->privatekey->pkey.ec;
				priv_key = EC_KEY_get0_private_key(tkey);
				if (priv_key == NULL)
					{
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
					goto err;
					}
				if (!EC_KEY_set_private_key(clnt_ecdh, priv_key))
					{
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_EC_LIB);
					goto err;
					}
				}
			else 
				{
				/* Generate a new ECDH key pair */
				if (!(EC_KEY_generate_key(clnt_ecdh)))
					{
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
		else if (alg_k & SSL_kGOST) 
			{
			/* GOST key exchange message creation */
			EVP_PKEY_CTX *pkey_ctx;
			X509 *peer_cert; 
			size_t msglen;
			unsigned int md_len;
			int keytype;
			unsigned char premaster_secret[32],shared_ukm[32], tmp[256];
			EVP_MD_CTX *ukm_hash;
			EVP_PKEY *pub_key;

			/* Get server sertificate PKEY and create ctx from it */
			peer_cert=s->session->sess_cert->peer_pkeys[(keytype=SSL_PKEY_GOST01)].x509;
			if (!peer_cert) 
				peer_cert=s->session->sess_cert->peer_pkeys[(keytype=SSL_PKEY_GOST94)].x509;
			if (!peer_cert)		{
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER);
					goto err;
				}	
				
			pkey_ctx=EVP_PKEY_CTX_new(pub_key=X509_get_pubkey(peer_cert),NULL);
			/* If we have send a certificate, and certificate key

			 * parameters match those of server certificate, use
			 * certificate key for key exchange
			 */

			 /* Otherwise, generate ephemeral key pair */
					
			EVP_PKEY_encrypt_init(pkey_ctx);
			  /* Generate session key */	
		    RAND_bytes(premaster_secret,32);
			/* If we have client certificate, use its secret as peer key */
			if (s->s3->tmp.cert_req && s->cert->key->privatekey) {
				if (EVP_PKEY_derive_set_peer(pkey_ctx,s->cert->key->privatekey) <=0) {
					/* If there was an error - just ignore it. Ephemeral key
					* would be used
					*/
					ERR_clear_error();
				}
			}			
			/* Compute shared IV and store it in algorithm-specific
			 * context data */
			ukm_hash = EVP_MD_CTX_create();
			EVP_DigestInit(ukm_hash,EVP_get_digestbynid(NID_id_GostR3411_94));
			EVP_DigestUpdate(ukm_hash,s->s3->client_random,SSL3_RANDOM_SIZE);
			EVP_DigestUpdate(ukm_hash,s->s3->server_random,SSL3_RANDOM_SIZE);
			EVP_DigestFinal_ex(ukm_hash, shared_ukm, &md_len);
			EVP_MD_CTX_destroy(ukm_hash);
			if (EVP_PKEY_CTX_ctrl(pkey_ctx,-1,EVP_PKEY_OP_ENCRYPT,EVP_PKEY_CTRL_SET_IV,
				8,shared_ukm)<0) {
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
						SSL_R_LIBRARY_BUG);
					goto err;
				}	
			/* Make GOST keytransport blob message */
			/*Encapsulate it into sequence */
			*(p++)=V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED;
			msglen=255;
			if (EVP_PKEY_encrypt(pkey_ctx,tmp,&msglen,premaster_secret,32)<0) {
			SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
					SSL_R_LIBRARY_BUG);
				goto err;
			}
			if (msglen >= 0x80)
				{
				*(p++)=0x81;
				*(p++)= msglen & 0xff;
				n=msglen+3;
				}
			else
				{
				*(p++)= msglen & 0xff;
				n=msglen+2;
				}
			memcpy(p, tmp, msglen);
			/* Check if pubkey from client certificate was used */
			if (EVP_PKEY_CTX_ctrl(pkey_ctx, -1, -1, EVP_PKEY_CTRL_PEER_KEY, 2, NULL) > 0)
				{
				/* Set flag "skip certificate verify" */
				s->s3->flags |= TLS1_FLAGS_SKIP_CERT_VERIFY;
				}
			EVP_PKEY_CTX_free(pkey_ctx);
			s->session->master_key_length=
				s->method->ssl3_enc->generate_master_secret(s,
					s->session->master_key,premaster_secret,32);
			EVP_PKEY_free(pub_key);

			}
#ifndef OPENSSL_NO_SRP
		else if (alg_k & SSL_kSRP)
			{
			if (s->srp_ctx.A != NULL)
				{
				/* send off the data */
				n=BN_num_bytes(s->srp_ctx.A);
				s2n(n,p);
				BN_bn2bin(s->srp_ctx.A,p);
				n+=2;
				}
			else
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_INTERNAL_ERROR);
				goto err;
				}
			if (s->session->srp_username != NULL)
				OPENSSL_free(s->session->srp_username);
			s->session->srp_username = BUF_strdup(s->srp_ctx.login);
			if (s->session->srp_username == NULL)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
					ERR_R_MALLOC_FAILURE);
				goto err;
				}

			if ((s->session->master_key_length = SRP_generate_client_master_secret(s,s->session->master_key))<0)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_INTERNAL_ERROR);
				goto err;
				}
			}
#endif
#ifndef OPENSSL_NO_PSK
		else if (alg_k & SSL_kPSK)
			{
			/* The callback needs PSK_MAX_IDENTITY_LEN + 1 bytes
			 * to return a \0-terminated identity. The last byte
			 * is for us for simulating strnlen. */
			char identity[PSK_MAX_IDENTITY_LEN + 2];
			size_t identity_len;
			unsigned char *t = NULL;
			unsigned char psk_or_pre_ms[PSK_MAX_PSK_LEN*2+4];
			unsigned int pre_ms_len = 0, psk_len = 0;
			int psk_err = 1;

			n = 0;
			if (s->psk_client_callback == NULL)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
					SSL_R_PSK_NO_CLIENT_CB);
				goto err;
				}

			memset(identity, 0, sizeof(identity));
			psk_len = s->psk_client_callback(s, s->ctx->psk_identity_hint,
				identity, sizeof(identity) - 1,
				psk_or_pre_ms, sizeof(psk_or_pre_ms));
			if (psk_len > PSK_MAX_PSK_LEN)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
					ERR_R_INTERNAL_ERROR);
				goto psk_err;
				}
			else if (psk_len == 0)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
					SSL_R_PSK_IDENTITY_NOT_FOUND);
				goto psk_err;
				}
			identity[PSK_MAX_IDENTITY_LEN + 1] = '\0';
			identity_len = strlen(identity);
			if (identity_len > PSK_MAX_IDENTITY_LEN)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
					ERR_R_INTERNAL_ERROR);
				goto psk_err;
				}
			/* create PSK pre_master_secret */
			pre_ms_len = 2+psk_len+2+psk_len;
			t = psk_or_pre_ms;
			memmove(psk_or_pre_ms+psk_len+4, psk_or_pre_ms, psk_len);
			s2n(psk_len, t);
			memset(t, 0, psk_len);
			t+=psk_len;
			s2n(psk_len, t);

			if (s->session->psk_identity_hint != NULL)
				OPENSSL_free(s->session->psk_identity_hint);
			s->session->psk_identity_hint = BUF_strdup(s->ctx->psk_identity_hint);
			if (s->ctx->psk_identity_hint != NULL &&
				s->session->psk_identity_hint == NULL)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
					ERR_R_MALLOC_FAILURE);
				goto psk_err;
				}

			if (s->session->psk_identity != NULL)
				OPENSSL_free(s->session->psk_identity);
			s->session->psk_identity = BUF_strdup(identity);
			if (s->session->psk_identity == NULL)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
					ERR_R_MALLOC_FAILURE);
				goto psk_err;
				}

			s->session->master_key_length =
				s->method->ssl3_enc->generate_master_secret(s,
					s->session->master_key,
					psk_or_pre_ms, pre_ms_len);
			s2n(identity_len, p);
			memcpy(p, identity, identity_len);
			n = 2 + identity_len;
			psk_err = 0;
		psk_err:
			OPENSSL_cleanse(identity, sizeof(identity));
			OPENSSL_cleanse(psk_or_pre_ms, sizeof(psk_or_pre_ms));
			if (psk_err != 0)
				{
				ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
				goto err;
				}
			}
#endif
		else
			{
			ssl3_send_alert(s, SSL3_AL_FATAL,
			    SSL_AD_HANDSHAKE_FAILURE);
			SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,
			    ERR_R_INTERNAL_ERROR);
			goto err;
			}
		
		*(d++)=SSL3_MT_CLIENT_KEY_EXCHANGE;
		l2n3(n,d);

		s->state=SSL3_ST_CW_KEY_EXCH_B;
		/* number of bytes to write */
		s->init_num=n+4;
		s->init_off=0;
		}

	/* SSL3_ST_CW_KEY_EXCH_B */
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

SPP_PROXY* spp_get_next_proxy(SSL *s) {
    int i;
    for (i = s->proxies_len - 1; i >= 0; i--) {
        if (s->proxies[i].done == 0) {
            return &(s->proxies[i]);
        }
    }
    return NULL;
}

int spp_get_proxy_done(SSL *s) {
    int ok,ret=0;
    long n;

    n=s->method->ssl_get_message(s,
        SPP_ST_CR_PRXY_DONE_A,
        SPP_ST_CR_PRXY_DONE_B,
        SSL3_MT_SERVER_DONE,
        30, /* should be very small, like 0 :-) */
        &ok);

    if (!ok) return((int)n);
    if (n > 0) {
        /* should contain no data */
        ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_DECODE_ERROR);
        SSLerr(SSL_F_SSL3_GET_SERVER_DONE,SSL_R_LENGTH_MISMATCH);
        return -1;
    }
    ret=1;
    return(ret);
}

int spp_get_proxy_key_exchange(SSL *s)
	{
#ifndef OPENSSL_NO_RSA
	unsigned char *q,md_buf[EVP_MAX_MD_SIZE*2];
#endif
	EVP_MD_CTX md_ctx;
	unsigned char *param,*p;
	int al,j,ok;
	long i,param_len,n,alg_k,alg_a;
	EVP_PKEY *pkey=NULL;
	const EVP_MD *md = NULL;
#ifndef OPENSSL_NO_RSA
	RSA *rsa=NULL;
#endif
#ifndef OPENSSL_NO_DH
	DH *dh=NULL;
#endif
#ifndef OPENSSL_NO_ECDH
	EC_KEY *ecdh = NULL;
	BN_CTX *bn_ctx = NULL;
	EC_POINT *srvr_ecpoint = NULL;
	int curve_nid = 0;
	int encoded_pt_len = 0;
#endif
        SPP_PROXY *proxy;

	/* use same message size as in ssl3_get_certificate_request()
	 * as ServerKeyExchange message may be skipped */
	n=s->method->ssl_get_message(s,
            SPP_ST_CR_PRXY_KEY_EXCH_A,
            SPP_ST_CR_PRXY_KEY_EXCH_B,
            -1,
            s->max_cert_list,
            &ok);
	if (!ok) return((int)n);

	if (s->s3->tmp.message_type != SSL3_MT_SERVER_KEY_EXCHANGE) {
            s->s3->tmp.reuse_message=1;
            return(1);
        }

	param=p=(unsigned char *)s->init_msg;
        proxy = spp_get_next_proxy(s);
        if (proxy == NULL) {
            SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SPP_R_INVALID_PROXY_ID);
            goto f_err;
        }
        
	if (proxy->sess_cert != NULL) {
#ifndef OPENSSL_NO_RSA
            if (proxy->sess_cert->peer_rsa_tmp != NULL) {
                RSA_free(proxy->sess_cert->peer_rsa_tmp);
                proxy->sess_cert->peer_rsa_tmp=NULL;
            }
#endif
#ifndef OPENSSL_NO_DH
            if (proxy->sess_cert->peer_dh_tmp) {
                DH_free(proxy->sess_cert->peer_dh_tmp);
                proxy->sess_cert->peer_dh_tmp=NULL;
            }
#endif
#ifndef OPENSSL_NO_ECDH
            if (proxy->sess_cert->peer_ecdh_tmp) {
                EC_KEY_free(proxy->sess_cert->peer_ecdh_tmp);
                proxy->sess_cert->peer_ecdh_tmp=NULL;
            }
#endif
        } else {
            proxy->sess_cert=ssl_sess_cert_new();
        }

	/* Total length of the parameters including the length prefix */
	param_len=0;

	alg_k=s->s3->tmp.new_cipher->algorithm_mkey;
	alg_a=s->s3->tmp.new_cipher->algorithm_auth;
	EVP_MD_CTX_init(&md_ctx);

	al=SSL_AD_DECODE_ERROR;

#ifndef OPENSSL_NO_DH
	if (alg_k & SSL_kEDH) {
            if ((dh=DH_new()) == NULL) {
                SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_DH_LIB);
                goto err;
            }

            param_len = 2;
            if (param_len > n) {
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
				SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		n2s(p,i);

		if (i > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_DH_P_LENGTH);
			goto f_err;
			}
		param_len += i;

		if (!(dh->p=BN_bin2bn(p,i,NULL)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;

		if (2 > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
				SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		param_len += 2;

		n2s(p,i);

		if (i > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_DH_G_LENGTH);
			goto f_err;
			}
		param_len += i;

		if (!(dh->g=BN_bin2bn(p,i,NULL)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;

		if (2 > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
				SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		param_len += 2;

		n2s(p,i);

		if (i > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_DH_PUB_KEY_LENGTH);
			goto f_err;
			}
		param_len += i;

		if (!(dh->pub_key=BN_bin2bn(p,i,NULL)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;
		n-=param_len;

#ifndef OPENSSL_NO_RSA
		if (alg_a & SSL_aRSA)
			pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
#else
		if (0)
			;
#endif
#ifndef OPENSSL_NO_DSA
		else if (alg_a & SSL_aDSS)
			pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_DSA_SIGN].x509);
#endif
		/* else anonymous DH, so no certificate or pkey. */

		s->session->sess_cert->peer_dh_tmp=dh;
		dh=NULL;
		}
	else if ((alg_k & SSL_kDHr) || (alg_k & SSL_kDHd))
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_TRIED_TO_USE_UNSUPPORTED_CIPHER);
		goto f_err;
		}
#endif /* !OPENSSL_NO_DH */

#ifndef OPENSSL_NO_ECDH
	else if (alg_k & SSL_kEECDH)
		{
		EC_GROUP *ngroup;
		const EC_GROUP *group;

		if ((ecdh=EC_KEY_new()) == NULL)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
			goto err;
			}

		/* Extract elliptic curve parameters and the
		 * server's ephemeral ECDH public key.
		 * Keep accumulating lengths of various components in
		 * param_len and make sure it never exceeds n.
		 */

		/* XXX: For now we only support named (not generic) curves
		 * and the ECParameters in this case is just three bytes. We
		 * also need one byte for the length of the encoded point
		 */
		param_len=4;
		if (param_len > n)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
				SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}

		if ((*p != NAMED_CURVE_TYPE) || 
		    ((curve_nid = tls1_ec_curve_id2nid(*(p + 2))) == 0))
			{
			al=SSL_AD_INTERNAL_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS);
			goto f_err;
			}

		ngroup = EC_GROUP_new_by_curve_name(curve_nid);
		if (ngroup == NULL)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_EC_LIB);
			goto err;
			}
		if (EC_KEY_set_group(ecdh, ngroup) == 0)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_EC_LIB);
			goto err;
			}
		EC_GROUP_free(ngroup);

		group = EC_KEY_get0_group(ecdh);

		if (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) &&
		    (EC_GROUP_get_degree(group) > 163))
			{
			al=SSL_AD_EXPORT_RESTRICTION;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_ECGROUP_TOO_LARGE_FOR_CIPHER);
			goto f_err;
			}

		p+=3;

		/* Next, get the encoded ECPoint */
		if (((srvr_ecpoint = EC_POINT_new(group)) == NULL) ||
		    ((bn_ctx = BN_CTX_new()) == NULL))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
			goto err;
			}

		encoded_pt_len = *p;  /* length of encoded point */
		p+=1;

		if ((encoded_pt_len > n - param_len) ||
		    (EC_POINT_oct2point(group, srvr_ecpoint, 
			p, encoded_pt_len, bn_ctx) == 0))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_ECPOINT);
			goto f_err;
			}
		param_len += encoded_pt_len;

		n-=param_len;
		p+=encoded_pt_len;

		/* The ECC/TLS specification does not mention
		 * the use of DSA to sign ECParameters in the server
		 * key exchange message. We do support RSA and ECDSA.
		 */
		if (0) ;
#ifndef OPENSSL_NO_RSA
		else if (alg_a & SSL_aRSA)
			pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
#endif
#ifndef OPENSSL_NO_ECDSA
		else if (alg_a & SSL_aECDSA)
			pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_ECC].x509);
#endif
		/* else anonymous ECDH, so no certificate or pkey. */
		EC_KEY_set_public_key(ecdh, srvr_ecpoint);
		s->session->sess_cert->peer_ecdh_tmp=ecdh;
		ecdh=NULL;
		BN_CTX_free(bn_ctx);
		bn_ctx = NULL;
		EC_POINT_free(srvr_ecpoint);
		srvr_ecpoint = NULL;
		}
	else if (alg_k)
		{
		al=SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_UNEXPECTED_MESSAGE);
		goto f_err;
		}
#endif /* !OPENSSL_NO_ECDH */


	/* p points to the next byte, there are 'n' bytes left */

	/* if it was signed, check the signature */
	if (pkey != NULL)
		{
		if (TLS1_get_version(s) >= TLS1_2_VERSION)
			{
			int sigalg;
			if (2 > n)
				{
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
					SSL_R_LENGTH_TOO_SHORT);
				goto f_err;
				}

			sigalg = tls12_get_sigid(pkey);
			/* Should never happen */
			if (sigalg == -1)
				{
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_INTERNAL_ERROR);
				goto err;
				}
			/* Check key type is consistent with signature */
			if (sigalg != (int)p[1])
				{
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_WRONG_SIGNATURE_TYPE);
				al=SSL_AD_DECODE_ERROR;
				goto f_err;
				}
			md = tls12_get_hash(p[0]);
			if (md == NULL)
				{
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_UNKNOWN_DIGEST);
				goto f_err;
				}
#ifdef SSL_DEBUG
fprintf(stderr, "USING TLSv1.2 HASH %s\n", EVP_MD_name(md));
#endif
			p += 2;
			n -= 2;
			}
		else
			md = EVP_sha1();

		if (2 > n)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,
				SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		n2s(p,i);
		n-=2;
		j=EVP_PKEY_size(pkey);

		/* Check signature length. If n is 0 then signature is empty */
		if ((i != n) || (n > j) || (n <= 0))
			{
			/* wrong packet length */
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_WRONG_SIGNATURE_LENGTH);
			goto f_err;
			}

#ifndef OPENSSL_NO_RSA
		if (pkey->type == EVP_PKEY_RSA && TLS1_get_version(s) < TLS1_2_VERSION)
			{
			int num;
			unsigned int size;

			j=0;
			q=md_buf;
			for (num=2; num > 0; num--)
				{
				EVP_MD_CTX_set_flags(&md_ctx,
					EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
				EVP_DigestInit_ex(&md_ctx,(num == 2)
					?s->ctx->md5:s->ctx->sha1, NULL);
				EVP_DigestUpdate(&md_ctx,&(s->s3->client_random[0]),SSL3_RANDOM_SIZE);
				EVP_DigestUpdate(&md_ctx,&(s->s3->server_random[0]),SSL3_RANDOM_SIZE);
				EVP_DigestUpdate(&md_ctx,param,param_len);
				EVP_DigestFinal_ex(&md_ctx,q,&size);
				q+=size;
				j+=size;
				}
			i=RSA_verify(NID_md5_sha1, md_buf, j, p, n,
								pkey->pkey.rsa);
			if (i < 0)
				{
				al=SSL_AD_DECRYPT_ERROR;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_RSA_DECRYPT);
				goto f_err;
				}
			if (i == 0)
				{
				/* bad signature */
				al=SSL_AD_DECRYPT_ERROR;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_SIGNATURE);
				goto f_err;
				}
			}
		else
#endif
			{
			EVP_VerifyInit_ex(&md_ctx, md, NULL);
			EVP_VerifyUpdate(&md_ctx,&(s->s3->client_random[0]),SSL3_RANDOM_SIZE);
			EVP_VerifyUpdate(&md_ctx,&(s->s3->server_random[0]),SSL3_RANDOM_SIZE);
			EVP_VerifyUpdate(&md_ctx,param,param_len);
			if (EVP_VerifyFinal(&md_ctx,p,(int)n,pkey) <= 0)
				{
				/* bad signature */
				al=SSL_AD_DECRYPT_ERROR;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_SIGNATURE);
				goto f_err;
				}
			}
		}
	else
		{
		/* aNULL, aSRP or kPSK do not need public keys */
		if (!(alg_a & (SSL_aNULL|SSL_aSRP)) && !(alg_k & SSL_kPSK))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_INTERNAL_ERROR);
			goto err;
			}
		/* still data left over */
		if (n != 0)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_EXTRA_DATA_IN_MESSAGE);
			goto f_err;
			}
		}
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_cleanup(&md_ctx);
	return(1);
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
err:
	EVP_PKEY_free(pkey);
#ifndef OPENSSL_NO_RSA
	if (rsa != NULL)
		RSA_free(rsa);
#endif
#ifndef OPENSSL_NO_DH
	if (dh != NULL)
		DH_free(dh);
#endif
#ifndef OPENSSL_NO_ECDH
	BN_CTX_free(bn_ctx);
	EC_POINT_free(srvr_ecpoint);
	if (ecdh != NULL)
		EC_KEY_free(ecdh);
#endif
	EVP_MD_CTX_cleanup(&md_ctx);
	return(-1);
	}

int spp_get_proxy_certificate(SSL *s) {
    int al,i,ok,ret= -1;
    unsigned long n,nc,llen,l;
    X509 *x=NULL;
    const unsigned char *q,*p;
    unsigned char *d;
    STACK_OF(X509) *sk=NULL;
    SESS_CERT *sc;
    SPP_PROXY *proxy;
    EVP_PKEY *pkey=NULL;
    int need_cert = 1; /* VRS: 0=> will allow null cert if auth == KRB5 */

    n=s->method->ssl_get_message(s,
        SPP_ST_CR_PRXY_CERT_A,
        SPP_ST_CR_PRXY_CERT_B,
        -1,
        s->max_cert_list,
        &ok);

    if (!ok) return((int)n);

    if ((s->s3->tmp.message_type == SSL3_MT_SERVER_KEY_EXCHANGE) ||
    ((s->s3->tmp.new_cipher->algorithm_auth & SSL_aKRB5) && 
    (s->s3->tmp.message_type == SSL3_MT_SERVER_DONE))) {
        s->s3->tmp.reuse_message=1;
        return(1);
    }

    if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE) {
        al=SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_BAD_MESSAGE_TYPE);
        goto f_err;
    }
    p=d=(unsigned char *)s->init_msg;

    if ((sk=sk_X509_new_null()) == NULL) {
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,ERR_R_MALLOC_FAILURE);
        goto err;
    }

    proxy = spp_get_next_proxy(s);
    if (proxy == NULL) {
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SPP_R_INVALID_PROXY_ID);
        goto f_err;
    }

    n2l3(p,llen);
    if (llen+3 != n) {
        al=SSL_AD_DECODE_ERROR;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_LENGTH_MISMATCH);
        goto f_err;
    }
    for (nc=0; nc<llen; ) {
        n2l3(p,l);
        if ((l+nc+3) > llen) {
            al=SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_CERT_LENGTH_MISMATCH);
            goto f_err;
        }

        q=p;
        x=d2i_X509(NULL,&q,l);
        if (x == NULL) {
            al=SSL_AD_BAD_CERTIFICATE;
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,ERR_R_ASN1_LIB);
            goto f_err;
        }
        if (q != (p+l)) {
            al=SSL_AD_DECODE_ERROR;
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_CERT_LENGTH_MISMATCH);
            goto f_err;
        }
        if (!sk_X509_push(sk,x)) {
            SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,ERR_R_MALLOC_FAILURE);
            goto err;
        }
        x=NULL;
        nc+=l+3;
        p=q;
    }

    i=ssl_verify_cert_chain(s,sk);
    if ((s->verify_mode != SSL_VERIFY_NONE) && (i <= 0) ) {
        al=ssl_verify_alarm_type(s->verify_result);
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_CERTIFICATE_VERIFY_FAILED);
        goto f_err; 
    }
    ERR_clear_error(); /* but we keep s->verify_result */

    sc=ssl_sess_cert_new();
    if (sc == NULL) goto err;

    if (proxy->sess_cert) ssl_sess_cert_free(proxy->sess_cert);
    proxy->sess_cert=sc;

    sc->cert_chain=sk;
    /* Inconsistency alert: cert_chain does include the peer's
     * certificate, which we don't include in s3_srvr.c */
    x=sk_X509_value(sk,0);
    sk=NULL;
    /* VRS 19990621: possible memory leak; sk=null ==> !sk_pop_free() @end*/

    pkey=X509_get_pubkey(x);

    /* VRS: allow null cert if auth == KRB5 */
    need_cert = 1;

    if (need_cert && ((pkey == NULL) || EVP_PKEY_missing_parameters(pkey))) {
        x=NULL;
        al=SSL3_AL_FATAL;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
                SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS);
        goto f_err;
    }

    i=ssl_cert_type(x,pkey);
    if (need_cert && i < 0) {
        x=NULL;
        al=SSL3_AL_FATAL;
        SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,
                SSL_R_UNKNOWN_CERTIFICATE_TYPE);
        goto f_err;
    }

    if (need_cert) {
        sc->peer_cert_type=i;
        CRYPTO_add(&x->references,1,CRYPTO_LOCK_X509);
        /* Why would the following ever happen?
         * We just created sc a couple of lines ago. */
        if (sc->peer_pkeys[i].x509 != NULL)
                X509_free(sc->peer_pkeys[i].x509);
        sc->peer_pkeys[i].x509=x;
        sc->peer_key= &(sc->peer_pkeys[i]);

        CRYPTO_add(&x->references,1,CRYPTO_LOCK_X509);
        proxy->peer=x;
    } else {
        sc->peer_cert_type=i;
        sc->peer_key= NULL;
        proxy->peer=NULL;
    }

    x=NULL;
    ret=1;

    if (0)
            {
f_err:
            ssl3_send_alert(s,SSL3_AL_FATAL,al);
            }
err:
    EVP_PKEY_free(pkey);
    X509_free(x);
    sk_X509_pop_free(sk,X509_free);
    return(ret);
}