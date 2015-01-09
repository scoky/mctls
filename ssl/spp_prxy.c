#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

static const SSL_METHOD *spp_get_proxy_method(int ver);
static const SSL_METHOD *spp_get_proxy_method(int ver)
	{
	if (ver == SPP_VERSION)
		return SPP_proxy_method();
	return NULL;
	}

IMPLEMENT_spp_meth_func(SPP_VERSION, SPP_proxy_method,
			spp_proxy_accept,
			ssl_undefined_function,
			spp_get_proxy_method)

char * spp_next_proxy_address(SSL *s) {
    int i;
    for (i = 0; i < s->proxies_len; i++) {
        if (strcmp(s->proxies[i]->address, s->proxy_address) == 0) {
            s->proxy_id = s->proxies[i]->proxy_id;
            break;
        }
    }
    // End the proxy list
    if (i < s->proxies_len-1) {
        return s->proxies[i+1]->address;
    } else if (i == s->proxies_len-1) {
        // Last proxy, return server
        return s->tlsext_hostname;
    } else {
        return NULL;
    }
}

int spp_initialize_ssl(SSL *s, SSL *n) {
    int ret = 1, i;
    BUF_MEM *buf=NULL;
    // Initialize the new SSL state
    s->other_ssl = n;
    n->other_ssl = s;
    n->proxy_id = s->proxy_id;
    n->proxy = 1;
    n->server = 0;
    
    if (n->handshake_func == 0)
        /* Not properly initialized yet */
        SSL_set_connect_state(n);
    
    n->version=SPP_VERSION;
    n->type=SSL_ST_CONNECT;

    if (n->init_buf == NULL) {
        if ((buf=BUF_MEM_new()) == NULL) {
            ret= -1;
            goto end;
        }
        if (!BUF_MEM_grow(buf,SSL3_RT_MAX_PLAIN_LENGTH)) {
            ret= -1;
            goto end;
        }
        n->init_buf=buf;
        buf=NULL;
    }

    if (!ssl3_setup_buffers(n)) { ret= -1; goto end; }

    /* setup buffing BIO */
    if (!ssl_init_wbio_buffer(n,0)) { ret= -1; goto end; }
    
    /* Copy proxies and slices */
    for (i = 0; i < s->proxies_len; i++) {
        n->proxies[i] = (SPP_PROXY*)malloc(sizeof(SPP_PROXY));
        spp_init_proxy(n->proxies[i]);
        n->proxies[i]->proxy_id = s->proxies[i]->proxy_id;
        n->proxies[i]->address = s->proxies[i]->address;
    }
    for (i = 0; i < s->slices_len; i++) {
        n->slices[i] = (SPP_SLICE*)malloc(sizeof(SPP_SLICE));
        spp_init_slice(n->slices[i]);
        n->slices[i]->slice_id = s->slices[i]->slice_id;
        n->slices[i]->purpose = s->slices[i]->purpose;
    }

end:
    return ret;
}

void spp_proxies_count(SSL *s, int *ahead, int *behind) {
    int i;
    for (i = 0; i < s->proxies_len; i++) {
        if (s->proxies[i]->proxy_id == s->proxy_id) {
            break;
        }
    }
    *ahead = i;
    *behind = s->proxies_len - i - 1;
}

/* The below functions are essentially identical except for an offset.
 * The read and write calls provided by openssl for handshake messages 
 * are inconsistent in whether the 4 byte header is included or not. */
int spp_forward_message(SSL *to, SSL*from) {
    unsigned char tBuf=(unsigned char *)to->init_buf->data;
    unsigned char *fBuf = (unsigned char *)from->init_buf->data;
    // When receiving a message, the helper functions automatically strip the header.
    to->init_num = from->init_num + 4;
    to->init_off = from->init_off;
    memcpy(tBuf, fBuf, to->init_num);    
    return(ssl3_do_write(to,SSL3_RT_HANDSHAKE));
}
int spp_duplicate_message(SSL *to, SSL*from) {
    unsigned char tBuf=(unsigned char *)to->init_buf->data;
    unsigned char *fBuf = (unsigned char *)from->init_buf->data;
    to->init_num = from->init_num;
    to->init_off = from->init_off;
    memcpy(tBuf, fBuf, to->init_num);    
    return(ssl3_do_write(to,SSL3_RT_HANDSHAKE));
}

/* Grab a handshake message from one state and forward it to the other. */
int get_proxy_msg(SSL *s, int st1, int stn, int msg) {
    int n, ok;
    n=s->method->ssl_get_message(s,
        st1,
        stn,
        msg,
        SSL3_RT_MAX_PLAIN_LENGTH,
        &ok);
    if (!ok) return n;
    spp_forward_message(s->other_ssl, s);
    
    return 1;
}

int spp_process_server_hello(SSL *s)
	{
	STACK_OF(SSL_CIPHER) *sk;
	const SSL_CIPHER *c;
	unsigned char *p,*d;
	int i,al,ok;
	unsigned int j;
	long n;
#ifndef OPENSSL_NO_COMP
	SSL_COMP *comp;
#endif

	n=s->method->ssl_get_message(s,
		SSL3_ST_CR_SRVR_HELLO_A,
		SSL3_ST_CR_SRVR_HELLO_B,
		-1,
		20000, /* ?? */
		&ok);

	if (!ok) return((int)n);

	if ( SSL_version(s) == DTLS1_VERSION || SSL_version(s) == DTLS1_BAD_VER)
		{
		if ( s->s3->tmp.message_type == DTLS1_MT_HELLO_VERIFY_REQUEST)
			{
			if ( s->d1->send_cookie == 0)
				{
				s->s3->tmp.reuse_message = 1;
				return 1;
				}
			else /* already sent a cookie */
				{
				al=SSL_AD_UNEXPECTED_MESSAGE;
				SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_BAD_MESSAGE_TYPE);
				goto f_err;
				}
			}
		}
	
	if ( s->s3->tmp.message_type != SSL3_MT_SERVER_HELLO)
		{
		al=SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_BAD_MESSAGE_TYPE);
		goto f_err;
		}

	d=p=(unsigned char *)s->init_msg;

	if ((p[0] != (s->version>>8)) || (p[1] != (s->version&0xff)))
		{
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_WRONG_SSL_VERSION);
		s->version=(s->version&0xff00)|p[1];
		al=SSL_AD_PROTOCOL_VERSION;
		goto f_err;
		}
	p+=2;

	/* load the server hello data */
	/* load the server random */
	memcpy(s->s3->server_random,p,SSL3_RANDOM_SIZE);
	p+=SSL3_RANDOM_SIZE;

	/* get the session-id */
	j= *(p++);

	if ((j > sizeof s->session->session_id) || (j > SSL3_SESSION_ID_SIZE))
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_SSL3_SESSION_ID_TOO_LONG);
		goto f_err;
		}

#ifndef OPENSSL_NO_TLSEXT
	/* check if we want to resume the session based on external pre-shared secret */
	if (s->version >= TLS1_VERSION && s->tls_session_secret_cb)
		{
		SSL_CIPHER *pref_cipher=NULL;
		s->session->master_key_length=sizeof(s->session->master_key);
		if (s->tls_session_secret_cb(s, s->session->master_key,
					     &s->session->master_key_length,
					     NULL, &pref_cipher,
					     s->tls_session_secret_cb_arg))
			{
			s->session->cipher = pref_cipher ?
				pref_cipher : ssl_get_cipher_by_char(s, p+j);
	    		s->s3->flags |= SSL3_FLAGS_CCS_OK;
			}
		}
#endif /* OPENSSL_NO_TLSEXT */

	if (j != 0 && j == s->session->session_id_length
	    && memcmp(p,s->session->session_id,j) == 0)
	    {
	    if(s->sid_ctx_length != s->session->sid_ctx_length
	       || memcmp(s->session->sid_ctx,s->sid_ctx,s->sid_ctx_length))
		{
		/* actually a client application bug */
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT);
		goto f_err;
		}
	    s->s3->flags |= SSL3_FLAGS_CCS_OK;
	    s->hit=1;
	    }
	else	/* a miss or crap from the other end */
		{
		/* If we were trying for session-id reuse, make a new
		 * SSL_SESSION so we don't stuff up other people */
		s->hit=0;
		if (s->session->session_id_length > 0)
			{
			if (!ssl_get_new_session(s,0))
				{
				al=SSL_AD_INTERNAL_ERROR;
				goto f_err;
				}
			}
		s->session->session_id_length=j;
		memcpy(s->session->session_id,p,j); /* j could be 0 */
		}
	p+=j;
	c=ssl_get_cipher_by_char(s,p);
	if (c == NULL)
		{
		/* unknown cipher */
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_UNKNOWN_CIPHER_RETURNED);
		goto f_err;
		}
	/* TLS v1.2 only ciphersuites require v1.2 or later */
	if ((c->algorithm_ssl & SSL_TLSV1_2) && 
		(TLS1_get_version(s) < TLS1_2_VERSION))
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_WRONG_CIPHER_RETURNED);
		goto f_err;
		}
#ifndef OPENSSL_NO_SRP
	if (((c->algorithm_mkey & SSL_kSRP) || (c->algorithm_auth & SSL_aSRP)) &&
		    !(s->srp_ctx.srp_Mask & SSL_kSRP))
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_WRONG_CIPHER_RETURNED);
		goto f_err;
		}
#endif /* OPENSSL_NO_SRP */
	p+=ssl_put_cipher_by_char(s,NULL,NULL);

	sk=ssl_get_ciphers_by_id(s);
	i=sk_SSL_CIPHER_find(sk,c);
	if (i < 0)
		{
		/* we did not say we would use this cipher */
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_WRONG_CIPHER_RETURNED);
		goto f_err;
		}

	/* Depending on the session caching (internal/external), the cipher
	   and/or cipher_id values may not be set. Make sure that
	   cipher_id is set and use it for comparison. */
	if (s->session->cipher)
		s->session->cipher_id = s->session->cipher->id;
	if (s->hit && (s->session->cipher_id != c->id))
		{
/* Workaround is now obsolete */
#if 0
		if (!(s->options &
			SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG))
#endif
			{
			al=SSL_AD_ILLEGAL_PARAMETER;
			SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED);
			goto f_err;
			}
		}
	s->s3->tmp.new_cipher=c;
	/* Don't digest cached records if TLS v1.2: we may need them for
	 * client authentication.
	 */
	if (TLS1_get_version(s) < TLS1_2_VERSION && !ssl3_digest_cached_records(s))
		{
		al = SSL_AD_INTERNAL_ERROR;
		goto f_err;
		}
	/* lets get the compression algorithm */
	/* COMPRESSION */
#ifdef OPENSSL_NO_COMP
	if (*(p++) != 0)
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
		goto f_err;
		}
	/* If compression is disabled we'd better not try to resume a session
	 * using compression.
	 */
	if (s->session->compress_meth != 0)
		{
		al=SSL_AD_INTERNAL_ERROR;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_INCONSISTENT_COMPRESSION);
		goto f_err;
		}
#else
	j= *(p++);
	if (s->hit && j != s->session->compress_meth)
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED);
		goto f_err;
		}
	if (j == 0)
		comp=NULL;
	else if (s->options & SSL_OP_NO_COMPRESSION)
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_COMPRESSION_DISABLED);
		goto f_err;
		}
	else
		comp=ssl3_comp_find(s->ctx->comp_methods,j);
	
	if ((j != 0) && (comp == NULL))
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
		goto f_err;
		}
	else
		{
		s->s3->tmp.new_compression=comp;
		}
#endif

#ifndef OPENSSL_NO_TLSEXT
	/* TLS extensions*/
	if (s->version >= SSL3_VERSION)
		{
		if (!ssl_parse_serverhello_tlsext(s,&p,d,n, &al))
			{
			/* 'al' set by ssl_parse_serverhello_tlsext */
			SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_PARSE_TLSEXT);
			goto f_err; 
			}
		if (ssl_check_serverhello_tlsext(s) <= 0)
			{
			SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_SERVERHELLO_TLSEXT);
				goto err;
			}
		}
#endif

	if (p != (d+n))
		{
		/* wrong packet length */
		al=SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_BAD_PACKET_LENGTH);
		goto f_err;
		}

	return(1);
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
err:
	return(-1);
	}

int get_proxy_material(SSL *s, int server) {
    int slice_id, proxy_id, len;
    unsigned char * param, *p;
    SPP_SLICE *slice, *slice2;
    
    param=p=(unsigned char *)s->init_msg;
    
    /* Server or client identifier */
    printf("PROXY MAT MSG header %d, %d, %d, %d\n", p[0], p[1], p[2], p[3]);
    n1s(p, proxy_id);
    
    // Message is not for this proxy, ignore it
    if (proxy_id != s->proxy_id) {
        return 1;
    }
    
    /* More to read */
    while (p-param < s->init_num) {
        n1s(p, slice_id);
        printf("Slice %d received\n", slice_id);
        slice = SPP_get_slice_by_id(s, slice_id);
        slice2 = SPP_get_slice_by_id(s->other_ssl, slice_id);
        if (slice == NULL)            
            goto err;
        
        n2s(p, len);
        if (len > EVP_MAX_KEY_LENGTH)
            goto err;
        if (len > 0) {
            if (server) {
                memcpy(slice->other_read_mat, p, len);
                memcpy(slice2->other_read_mat, p, len);
            } else {
                memcpy(slice->read_mat, p, len);
                memcpy(slice2->read_mat, p, len);
            }
            p += len;
            slice->read_access = 1;
            slice2->read_access = 1;
        }
        
        n2s(p, len);
        if (len > EVP_MAX_KEY_LENGTH)
            goto err;
        if (len> 0) {
            if (server) {
                memcpy(slice->other_write_mat, p, len);
                memcpy(slice2->other_write_mat, p, len);
            }
            p += len;
            slice->write_access = 1;
            slice2->write_access = 1;
        }
        
    }
    /* Should now have read the full message. */
    if (p-param != s->init_num) {
        printf("Did not read the whole message, %d != %d\n", p-param, s->init_num);
        goto err;
    }
    
    return 1;
err:
    return(-1);
}

int spp_proxy_accept(SSL *s) {
    SSL *next_st;
    BUF_MEM *buf;
    char *address;
    SPP_PROXY *proxy=NULL, *this_proxy;
    unsigned long alg_k,Time=(unsigned long)time(NULL);
    void (*cb)(const SSL *ssl,int type,int val)=NULL;
    int ahead,behind;
    int ret= -1,i;
    int new_state,state,skip=0;

    RAND_add(&Time,sizeof(Time),0);
    ERR_clear_error();
    clear_sys_error();

    if (s->info_callback != NULL)
            cb=s->info_callback;
    else if (s->ctx->info_callback != NULL)
            cb=s->ctx->info_callback;

    /* init things to blank */
    s->in_handshake++;
    if (!SSL_in_init(s) || SSL_in_before(s)) SSL_clear(s);

    if (s->cert == NULL) {
        SSLerr(SSL_F_SSL3_ACCEPT,SSL_R_NO_CERTIFICATE_SET);
        return(-1);
    }

#ifndef OPENSSL_NO_HEARTBEATS
    /* If we're awaiting a HeartbeatResponse, pretend we
     * already got and don't await it anymore, because
     * Heartbeats don't make sense during handshakes anyway.
     */
    if (s->tlsext_hb_pending)
            {
            s->tlsext_hb_pending = 0;
            s->tlsext_hb_seq++;
            }
#endif

    for (;;) {
        state=s->state;

        switch (s->state) {
            case SSL_ST_RENEGOTIATE:
                s->renegotiate=1;
                /* s->state=SSL_ST_ACCEPT; */

            case SSL_ST_BEFORE:
            case SSL_ST_ACCEPT:
            case SSL_ST_BEFORE|SSL_ST_ACCEPT:
            case SSL_ST_OK|SSL_ST_ACCEPT:
                printf("Before state\n");
                s->server = 1;
                s->proxy = 1;
                //s->proxy_id = 2;

                if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_START,1);

                if ((s->version>>8) != 6) {
                    SSLerr(SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
                    return -1;
                }
                s->type=SSL_ST_ACCEPT;

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
                }

                if (!ssl3_setup_buffers(s)) {
                    ret= -1;
                    goto end;
                }

                s->init_num=0;
                s->s3->flags &= ~SSL3_FLAGS_SGC_RESTART_DONE;

                if (s->state != SSL_ST_RENEGOTIATE) {
                    /* Ok, we now need to push on a buffering BIO so that
                     * the output is sent in a way that TCP likes :-)
                     */
                    if (!ssl_init_wbio_buffer(s,1)) { ret= -1; goto end; }
				
                    ssl3_init_finished_mac(s);
                    s->state=SSL3_ST_SR_CLNT_HELLO_A;
                    s->ctx->stats.sess_accept++;
                } else if (!s->s3->send_connection_binding && !(s->options & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)) {
                    /* Server attempting to renegotiate with
                     * client that doesn't support secure
                     * renegotiation.
                     */
                    SSLerr(SSL_F_SSL3_ACCEPT, SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
                    ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_HANDSHAKE_FAILURE);
                    ret = -1;
                    goto end;
                } else {
                    /* s->state == SSL_ST_RENEGOTIATE,
                     * we will just send a HelloRequest */
                    s->ctx->stats.sess_accept_renegotiate++;
                    s->state=SSL3_ST_SW_HELLO_REQ_A;
                }
                break;

            case SSL3_ST_SR_CLNT_HELLO_A:
            case SSL3_ST_SR_CLNT_HELLO_B:
            case SSL3_ST_SR_CLNT_HELLO_C:
                s->shutdown=0;
                if (s->rwstate != SSL_X509_LOOKUP) {
                    ret=ssl3_get_client_hello(s);
                    printf("Received client hello\n");
                    if (ret <= 0) goto end;
                }
                
                // Process locally and call application to start new connection
                if ((address = spp_next_proxy_address(s)) == NULL)
                    goto end;
                this_proxy = SPP_get_proxy_by_id(s, s->proxy_id);
                if ((next_st = s->proxy_func(s, address)) == NULL)
                    goto end;
                
                spp_initialize_ssl(s, next_st);
                
                // Forward the message on.
                ret=spp_forward_message(next_st, s);
                if (ret <= 0) goto end;
                
                s->renegotiate = 2;
                s->state=SSL3_ST_CR_SRVR_HELLO_A;
                s->init_num=0;
                break;
                
            case SSL3_ST_CR_SRVR_HELLO_A:
            case SSL3_ST_CR_SRVR_HELLO_B:
                // Must read from the hello to determine what ciphers are in use.
                ret=get_proxy_msg(next_st, SSL3_ST_CR_SRVR_HELLO_A, SSL3_ST_CR_SRVR_HELLO_B, SSL3_MT_SERVER_HELLO);
                printf("Received server hello\n");
                if (ret <= 0) goto end;
                ret=spp_process_server_hello(next_st);                
		if (ret <= 0) goto end;
                
                s->state=SSL3_ST_CR_CERT_A;
                s->init_num=next_st->init_num=0;
                break;

            case SSL3_ST_CR_CERT_A:
            case SSL3_ST_CR_CERT_B:
                ret=get_proxy_msg(next_st, SSL3_ST_CR_CERT_A, SSL3_ST_CR_CERT_B, SSL3_MT_CERTIFICATE);
                printf("Received server certificate\n");
                if (ret <= 0) goto end;
                
                s->state=SSL3_ST_CR_KEY_EXCH_A;
                s->init_num=next_st->init_num=0;
                break;

            case SSL3_ST_CR_KEY_EXCH_A:
            case SSL3_ST_CR_KEY_EXCH_B:
                ret=get_proxy_msg(next_st, SSL3_ST_CR_KEY_EXCH_A, SSL3_ST_CR_KEY_EXCH_B, SSL3_MT_SERVER_KEY_EXCHANGE);
                printf("Received server key exchange\n");
                if (ret <= 0) goto end;

                s->state=SSL3_ST_CR_SRVR_DONE_A;
                s->init_num=next_st->init_num=0;

                /* at this point we check that we have the
                 * required stuff from the server */
                if (!ssl3_check_cert_and_algorithm(next_st)) {
                    ret= -1;
                    goto end;
                }
                break;
                
            case SSL3_ST_CR_SRVR_DONE_A:
            case SSL3_ST_CR_SRVR_DONE_B:
                ret=get_proxy_msg(next_st, SSL3_ST_CR_SRVR_DONE_A, SSL3_ST_CR_SRVR_DONE_B, SSL3_MT_SERVER_DONE);
                printf("Received server done\n");
                if (ret <= 0) goto end;

                if (s->s3->tmp.cert_req)
                    goto end;
                else {
                    s->state=SPP_ST_PW_PRXY_CERT_A;
                }
                s->init_num=next_st->init_num=0;

                break;
                
            case SPP_ST_PW_PRXY_CERT_A:
            case SPP_ST_PW_PRXY_CERT_B:
                /* Check if it is anon DH or anon ECDH, */
                /* normal PSK or KRB5 or SRP */
                if (!(s->s3->tmp.new_cipher->algorithm_auth & (SSL_aNULL|SSL_aKRB5|SSL_aSRP))
                    && !(s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK)) {
                        printf("Sending certificate\n");
                        ret=ssl3_send_server_certificate(s);                        
                        if (ret <= 0) goto end;
                        ret=spp_duplicate_message(next_st, s);
                        if (ret <= 0) goto end;
                } else
                    skip=1;

                s->state=SPP_ST_PW_PRXY_KEY_EXCH_A;
                s->init_num=next_st->init_num=0;
                break;

            case SPP_ST_PW_PRXY_KEY_EXCH_A:
            case SPP_ST_PW_PRXY_KEY_EXCH_B:
                alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

                /* clear this, it may get reset by
                 * send_server_key_exchange */
                if ((s->options & SSL_OP_EPHEMERAL_RSA)
#ifndef OPENSSL_NO_KRB5
                    && !(alg_k & SSL_kKRB5)
#endif /* OPENSSL_NO_KRB5 */
                    )
                    /* option SSL_OP_EPHEMERAL_RSA sends temporary RSA key
                     * even when forbidden by protocol specs
                     * (handshake may fail as clients are not required to
                     * be able to handle this) */
                    s->s3->tmp.use_rsa_tmp=1;
                else
                    s->s3->tmp.use_rsa_tmp=0;


                /* only send if a DH key exchange, fortezza or
                 * RSA but we have a sign only certificate
                 *
                 * PSK: may send PSK identity hints
                 *
                 * For ECC ciphersuites, we send a serverKeyExchange
                 * message only if the cipher suite is either
                 * ECDH-anon or ECDHE. In other cases, the
                 * server certificate contains the server's
                 * public key for key exchange.
                 */
                if (s->s3->tmp.use_rsa_tmp
                /* PSK: send ServerKeyExchange if PSK identity
                 * hint if provided */
#ifndef OPENSSL_NO_PSK
                    || ((alg_k & SSL_kPSK) && s->ctx->psk_identity_hint)
#endif
#ifndef OPENSSL_NO_SRP
                    /* SRP: send ServerKeyExchange */
                    || (alg_k & SSL_kSRP)
#endif
                    || (alg_k & (SSL_kDHr|SSL_kDHd|SSL_kEDH))
                    || (alg_k & SSL_kEECDH)
                    || ((alg_k & SSL_kRSA)
                        && (s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL
                            || (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher)
                                && EVP_PKEY_size(s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey)*8 > SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)
                                )
                            )
                        )
                    )
                        {
                        printf("Sending server key exchange\n");
                        ret=ssl3_send_server_key_exchange(s);
                        if (ret <= 0) goto end;
                        ret=spp_duplicate_message(next_st, s);
                        if (ret <= 0) goto end;
                        }
                else
                        skip=1;

                s->state=SPP_ST_PW_PRXY_DONE_A;
                s->init_num=next_st->init_num=0;
                break;
                
            case SPP_ST_PW_PRXY_DONE_A:
            case SPP_ST_PW_PRXY_DONE_B:
                printf("Sending server done\n");
                ret=ssl3_send_server_done(s);
                printf("Sent server done\n");
                if (ret <= 0) goto end;
                ret=spp_duplicate_message(next_st, s);
                if (ret <= 0) goto end;
                                
                s->state=SSL3_ST_SW_FLUSH;
                s->init_num=next_st->init_num=0;
                
                // Receive and forward the certificates for proxies between us and the server
                if ((proxy = spp_get_next_proxy(s, this_proxy, 1)) != NULL) {
                    s->s3->tmp.next_state=SPP_ST_PR_BEHIND_A;
                } else if ((proxy = spp_get_next_proxy(s, this_proxy, 0)) != NULL) {
                    s->s3->tmp.next_state=SPP_ST_PR_AHEAD_A;
                } else {
                    s->s3->tmp.next_state=SSL3_ST_SR_KEY_EXCH_A;
                }
                break;

            case SPP_ST_PR_BEHIND_A:
            case SPP_ST_PR_BEHIND_B:
                printf("Waiting for behind proxy message\n");
                while (proxy != NULL) {
                    s->state=SPP_ST_PR_BEHIND_A;
                    ret=get_proxy_msg(next_st, SPP_ST_PR_BEHIND_A, SPP_ST_PR_BEHIND_B, -1);
                    printf("Received proxy message\n");
                    if (ret <= 0) goto end;
                    s->init_num=next_st->init_num=0;
                    if (next_st->s3->tmp.message_type == SSL3_MT_SERVER_DONE) {
                        if ((proxy = spp_get_next_proxy(s, proxy, 1)) == NULL) {
                            if ((proxy = spp_get_next_proxy(s, this_proxy, 0)) != NULL)
                                s->state=SPP_ST_PR_AHEAD_A;
                            else
                                s->state=SSL3_ST_SR_KEY_EXCH_A;
                            break;
                        }
                    }
                }
                
                break;
                
            case SPP_ST_PR_AHEAD_A:
            case SPP_ST_PR_AHEAD_B:
                printf("Waiting for ahead proxy message\n");
                while (proxy != NULL) {
                    s->state=SPP_ST_PR_AHEAD_A;
                    ret=get_proxy_msg(s, SPP_ST_PR_AHEAD_A, SPP_ST_PR_AHEAD_B, -1);
                    printf("Received proxy message\n");
                    if (ret <= 0) goto end;
                    s->init_num=next_st->init_num=0;
                    if (s->s3->tmp.message_type == SSL3_MT_SERVER_DONE) {
                        if ((proxy = spp_get_next_proxy(s, proxy, 0)) == NULL) {
                            s->s3->tmp.next_state=SSL3_ST_SR_KEY_EXCH_A;
                            break;
                        } 
                    }
                }
                
                break;
		
            case SSL3_ST_SW_FLUSH:
                /* This code originally checked to see if
                 * any data was pending using BIO_CTRL_INFO
                 * and then flushed. This caused problems
                 * as documented in PR#1939. The proposed
                 * fix doesn't completely resolve this issue
                 * as buggy implementations of BIO_CTRL_PENDING
                 * still exist. So instead we just flush
                 * unconditionally.
                 */

                s->rwstate=SSL_WRITING;
                if (BIO_flush(s->wbio) <= 0) {
                    ret= -1;
                    goto end;
                }
                s->rwstate=SSL_NOTHING;
                next_st->rwstate=SSL_WRITING;
                if (BIO_flush(next_st->wbio) <= 0) {
                    ret= -1;
                    goto end;
                }
                next_st->rwstate=SSL_NOTHING;

                s->state=s->s3->tmp.next_state;
                break;
                
            case SSL3_ST_SR_KEY_EXCH_A:
            case SSL3_ST_SR_KEY_EXCH_B:
                printf("Receiving client key exchange\n");
                ret=get_proxy_msg(s, SSL3_ST_SR_KEY_EXCH_A, SSL3_ST_SR_KEY_EXCH_B, SSL3_MT_CLIENT_KEY_EXCHANGE);
                printf("Received client key exchange\n");
                if (ret <= 0) goto end;
                
                s->state=SPP_ST_CR_PRXY_MAT_A;
                s->init_num=next_st->init_num=0;
                break;
                
            case SPP_ST_CR_PRXY_MAT_A:
            case SPP_ST_CR_PRXY_MAT_B:
                printf("Receiving proxy key material\n");
                // Receive proxy key material for each proxy and the server
                // Pass all messages on
                for (i = 0; i <= s->proxies_len; i++) {
                    s->state = SPP_ST_CR_PRXY_MAT_A;
                    ret=get_proxy_msg(s, SPP_ST_CR_PRXY_MAT_A, SPP_ST_CR_PRXY_MAT_B, SPP_MT_PROXY_KEY_MATERIAL);
                    if (ret <= 0) goto end;
                    ret=get_proxy_material(s, 0);
                    if (ret <= 0) goto end;
                }
                
                s->state=SPP_ST_SR_PRXY_MAT_A;
                s->init_num=next_st->init_num=0;
                break;
                
            case SPP_ST_SR_PRXY_MAT_A:
            case SPP_ST_SR_PRXY_MAT_B:
                printf("Receiving proxy key material\n");
                // Receive proxy key material for each proxy and the server
                // Pass all messages on
                for (i = 0; i <= s->proxies_len; i++) {
                    s->state = SPP_ST_SR_PRXY_MAT_A;
                    ret=get_proxy_msg(next_st, SPP_ST_SR_PRXY_MAT_A, SPP_ST_SR_PRXY_MAT_B, SPP_MT_PROXY_KEY_MATERIAL);
                    if (ret <= 0) goto end;
                    ret=get_proxy_material(next_st, 1);
                    if (ret <= 0) goto end;
                }
                
#if defined(OPENSSL_NO_TLSEXT) || defined(OPENSSL_NO_NEXTPROTONEG)
                s->state=SSL3_ST_SR_FINISHED_A;
#else
                if (s->s3->next_proto_neg_seen)
                    s->state=SSL3_ST_SR_NEXT_PROTO_A;
                else
                    s->state=SSL3_ST_SR_FINISHED_A;
#endif
                s->init_num=next_st->init_num=0;
                break;

#if !defined(OPENSSL_NO_TLSEXT) && !defined(OPENSSL_NO_NEXTPROTONEG)
            case SSL3_ST_SR_NEXT_PROTO_A:
            case SSL3_ST_SR_NEXT_PROTO_B:
                ret=get_proxy_msg(next_st, SSL3_ST_SR_NEXT_PROTO_A, SSL3_ST_SR_NEXT_PROTO_B, SSL3_MT_NEXT_PROTO);
                if (ret <= 0) goto end;
                s->init_num=next_st->init_num=0;
                s->state=SSL3_ST_SR_FINISHED_A;
                break;
#endif

            case SSL3_ST_SR_FINISHED_A:
            case SSL3_ST_SR_FINISHED_B:
                do {
                    s->s3->flags |= SSL3_FLAGS_CCS_OK;
                    s->state = SSL3_ST_SR_FINISHED_A;
                    ret=get_proxy_msg(s, SSL3_ST_SR_FINISHED_A, SSL3_ST_SR_FINISHED_B, -1);
                    if (ret <= 0) goto end;
                } while (s->s3->tmp.message_type != SSL3_MT_FINISHED);
                
                if (s->hit)
                    s->state=SSL_ST_OK;
#ifndef OPENSSL_NO_TLSEXT
                else if (s->tlsext_ticket_expected)
                    s->state=SSL3_ST_SW_SESSION_TICKET_A;
#endif
                else
                    s->state=SSL3_ST_CR_FINISHED_A;
                s->init_num=next_st->init_num=0;
                
                // Change cipher state BEFORE receiving finished message
                if (!s->method->ssl3_enc->change_cipher_state(s, SSL3_CHANGE_CIPHER_SERVER_WRITE)) {
                    ret= -1;
                    goto end;
                }
                break;
                
            case SSL3_ST_CR_FINISHED_A:
            case SSL3_ST_CR_FINISHED_B:
                do {
                    s->s3->flags |= SSL3_FLAGS_CCS_OK;
                    s->state = SSL3_ST_CR_FINISHED_A;
                    ret=get_proxy_msg(next_st, SSL3_ST_CR_FINISHED_A, SSL3_ST_CR_FINISHED_B, -1);
                    if (ret <= 0) goto end;
                } while (s->s3->tmp.message_type != SSL3_MT_FINISHED);
                
                if (s->hit)
                    s->state=SSL_ST_OK;
#ifndef OPENSSL_NO_TLSEXT
                else if (s->tlsext_ticket_expected)
                    s->state=SSL3_ST_SW_SESSION_TICKET_A;
#endif
                else
                    s->state=SSL_ST_OK;
                s->init_num=next_st->init_num=0;
                break;

            case SSL_ST_OK:
                /* clean a few things up */
                ssl3_cleanup_key_block(s);

                BUF_MEM_free(s->init_buf);
                s->init_buf=NULL;

                /* remove buffering on output */
                ssl_free_wbio_buffer(s);

                s->init_num=0;

                if (s->renegotiate == 2) /* skipped if we just sent a HelloRequest */
                        {
                        s->renegotiate=0;
                        s->new_session=0;

                        ssl_update_cache(s,SSL_SESS_CACHE_SERVER);

                        s->ctx->stats.sess_accept_good++;
                        /* s->server=1; */
                        s->handshake_func=ssl3_accept;

                        if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_DONE,1);
                        }

                ret = 1;
                goto end;
                /* break; */

            default:
                SSLerr(SSL_F_SSL3_ACCEPT,SSL_R_UNKNOWN_STATE);
                ret= -1;
                goto end;
                /* break; */
        }
		
        if (!s->s3->tmp.reuse_message && !skip) {
            if (s->debug) {
                if ((ret=BIO_flush(s->wbio)) <= 0)
                    goto end;
            }


            if ((cb != NULL) && (s->state != state)) {
                new_state=s->state;
                s->state=state;
                cb(s,SSL_CB_ACCEPT_LOOP,1);
                s->state=new_state;
            }
        }
        skip=0;
    }
end:
    printf("Handshake end\n");
    /* BIO_flush(s->wbio); */

    s->in_handshake--;
    if (next_st != NULL)
        next_st->in_handshake--;
    if (cb != NULL)
            cb(s,SSL_CB_ACCEPT_EXIT,ret);
    return(ret);
}

