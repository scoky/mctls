#include <limits.h>
#include <string.h>
#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

/* Matteo -- START*/
// Compute a time difference - NOTE: Return 1 if the difference is negative, otherwise 0
int timeval_subtract(struct timeval *result, struct timeval *t2, struct timeval *t1){
    long int diff = (t2->tv_usec + 1000000 * t2->tv_sec) - (t1->tv_usec + 1000000 * t1->tv_sec);
    result->tv_sec = diff / 1000000;
    result->tv_usec = diff % 1000000;

    return (diff<0);
}

// Compute a time difference - NOTE: Return 1 if the difference is negative, otherwise 0
void log_time(char *message, struct timeval *currTime, struct timeval *prevTime, struct timeval *originTime){
	// Local time passed variables
	struct timeval tPassed; 
 	struct timeval tPassedBeg;

 	// Get current time 
 	gettimeofday(currTime, NULL);	
 
 	// Compute time passed from last 
 	timeval_subtract(&tPassed, currTime, prevTime); 
 
 	// Compute time passed
 	timeval_subtract(&tPassedBeg, currTime, originTime);
 	
 	// Logging	
 	printf("[CURR_TIME=%ld.%06ld TIME_LAST=%ld.%06ld TIME_PASSED=%ld.%06ld]\t%s", (long int)(currTime->tv_sec), (long int)(currTime->tv_usec), (long int)(tPassed.tv_sec), (long int)(tPassed.tv_usec),(long int)(tPassedBeg.tv_sec), (long int)(tPassedBeg.tv_usec), message); 
 	
 	// Update previous time 
 	prevTime = currTime; 
 }
/* Matteo -- END*/

void spp_init_slice(SPP_SLICE *slice) {
    slice->read_ciph = slice->read_mac = slice->write_mac = NULL;
    slice->read_mat_len = slice->other_read_mat_len = slice->write_mat_len = slice->other_write_mat_len = 0;
    slice->purpose = NULL;
    slice->read_access = slice->write_access = 0;
    memset(&(slice->read_mat[0]), 0, sizeof(slice->read_mat));
    memset(&(slice->other_read_mat[0]), 0, sizeof(slice->other_read_mat));
    memset(&(slice->write_mat[0]), 0, sizeof(slice->write_mat));
    memset(&(slice->other_write_mat[0]), 0, sizeof(slice->other_write_mat));
}

void spp_init_proxy(SPP_PROXY *proxy) {
    proxy->session = proxy->sess_cert = proxy->peer = NULL;
    proxy->read_slice_ids_len = proxy->write_slice_ids_len = 0;
    proxy->address = NULL;
    proxy->done = 0;
    proxy->proxy_id = 0;
}

int spp_generate_slice_keys(SSL *s) {
    int i;    
    for (i = 0; i < s->slices_len; i++) {
        if (RAND_pseudo_bytes(&(s->slices[i]->read_mat[0]), EVP_MAX_KEY_LENGTH) <= 0)
            return -1;
        if (RAND_pseudo_bytes(&(s->slices[i]->write_mat[0]), EVP_MAX_KEY_LENGTH) <= 0)
            return -1;
    }
    return 1;
}

int spp_copy_mac_state(SSL *s, SPP_MAC *mac, int send) {    
    if (send) {
        if (mac == NULL) {
            s->write_hash = NULL;
            memset(s->s3->write_mac_secret, 0, EVP_MAX_MD_SIZE);
            memset(s->s3->write_sequence, 0, 8);
        } else {
            s->write_hash = mac->write_hash;
            memcpy(s->s3->write_mac_secret, mac->write_mac_secret, EVP_MAX_MD_SIZE);
            s->s3->write_mac_secret_size = mac->write_mac_secret_size;
            memcpy(s->s3->write_sequence, mac->write_sequence, 8);
        }
    } else {
        if (mac == NULL) {
            s->read_hash = NULL;
            memset(s->s3->read_mac_secret, 0, EVP_MAX_MD_SIZE);
            memset(s->s3->read_sequence, 0, 8);
        } else {
            s->read_hash = mac->read_hash;
            memcpy(s->s3->read_mac_secret, mac->read_mac_secret, EVP_MAX_MD_SIZE);
            s->s3->read_mac_secret_size = mac->read_mac_secret_size;
            memcpy(s->s3->read_sequence, mac->read_sequence, 8);
        }
    }
    return 1;
}
int spp_copy_mac_back(SSL *s, SPP_MAC *mac, int send) {
    if (mac == NULL)
        return 1;
    if (send) {
        //mac->write_hash = s->write_hash;
        //memcpy(mac->write_mac_secret, s->s3->write_mac_secret, EVP_MAX_MD_SIZE);
        //mac->write_mac_secret_size = s->s3->write_mac_secret_size;
        memcpy(mac->write_sequence, s->s3->write_sequence, 8);
    } else {
        //mac->read_hash = s->read_hash;
        //memcpy(mac->read_mac_secret, s->s3->read_mac_secret, EVP_MAX_MD_SIZE);
        //mac->read_mac_secret_size = s->s3->read_mac_secret_size;
        memcpy(mac->read_sequence, s->s3->read_sequence, 8);
    }
    return 1;
}
int spp_copy_ciph_state(SSL *s, SPP_CIPH *ciph, int send) {
    if (send) {
        s->enc_write_ctx = ciph->enc_write_ctx;
    } else {
        s->enc_read_ctx = ciph->enc_read_ctx;
    }
}

SPP_PROXY* spp_get_next_proxy(SSL *s, SPP_PROXY* proxy, int forward) {
    int i;
    if (s->proxies_len == 0) {
        return NULL;
    }
    
    if (forward) {
        // Return the first proxy
        if (proxy == NULL) {
            return s->proxies[0];
        }
        for (i = 0; i < s->proxies_len-1; i++) {
            if (s->proxies[i]->proxy_id == proxy->proxy_id) {
                return s->proxies[i+1];
            }
        }
    } else {
        // Return the last one
        if (proxy == NULL) {
            return s->proxies[s->proxies_len-1];
        }
        for (i = s->proxies_len - 1; i >= 1; i--) {
            if (s->proxies[i]->proxy_id == proxy->proxy_id) {
                return s->proxies[i-1];
            }
        }
    }
    return NULL;
}

int spp_get_proxy_certificate(SSL *s, SPP_PROXY* proxy) {
    int al,i,ok,ret= -1;
    unsigned long n,nc,llen,l;
    X509 *x=NULL;
    const unsigned char *q,*p;
    unsigned char *d;
    STACK_OF(X509) *sk=NULL;
    SESS_CERT *sc;
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

int spp_get_proxy_key_exchange(SSL *s, SPP_PROXY* proxy)
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
			pkey=X509_get_pubkey(proxy->sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
#else
		if (0)
			;
#endif
#ifndef OPENSSL_NO_DSA
		else if (alg_a & SSL_aDSS)
			pkey=X509_get_pubkey(proxy->sess_cert->peer_pkeys[SSL_PKEY_DSA_SIGN].x509);
#endif
		/* else anonymous DH, so no certificate or pkey. */

		proxy->sess_cert->peer_dh_tmp=dh;
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
			pkey=X509_get_pubkey(proxy->sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
#endif
#ifndef OPENSSL_NO_ECDSA
		else if (alg_a & SSL_aECDSA)
			pkey=X509_get_pubkey(proxy->sess_cert->peer_pkeys[SSL_PKEY_ECC].x509);
#endif
		/* else anonymous ECDH, so no certificate or pkey. */
		EC_KEY_set_public_key(ecdh, srvr_ecpoint);
		proxy->sess_cert->peer_ecdh_tmp=ecdh;
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

int spp_get_proxy_done(SSL *s, SPP_PROXY* proxy) {
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
    
    proxy->done = 1;
    
    ret=1;
    return(ret);
}

int spp_get_proxy_key_material(SSL *s, SPP_PROXY* proxy) { 
    /* This method does nothing. The client/server just read these messages 
     * which are actually intended for the proxies, and added them to the 
     * Finished message digest. The message contents should be ignored. */
    int n, ok;
    n=s->method->ssl_get_message(s,
        SPP_ST_CR_PRXY_MAT_A,
        SPP_ST_CR_PRXY_MAT_B,
        SPP_MT_PROXY_KEY_MATERIAL,
        SSL3_RT_MAX_PLAIN_LENGTH,
        &ok);
    if (!ok) return n;
    return 1;
}

int spp_send_proxy_key_material(SSL *s, SPP_PROXY* proxy) {
    unsigned char *p,*d;
    int n,i,j,found;
    SPP_SLICE *slice;
    EVP_PKEY *pub_key = NULL;
    EVP_PKEY **pub_keys = malloc(1 * sizeof(EVP_PKEY *));
    unsigned char shared_secret[EVP_MAX_KEY_LENGTH];
    // unsigned char *encrypted_key_mat = NULL;
    /* THIS PROBABLY NEEDS TO BE CHANGED TO BE MORE DYNAMIC AND HAVE THE REAL LENGTH*/
    unsigned char encrypted_key_mat[1024];
    int encrypted_key_mat_len = 0; //[1] = {0};
    unsigned char envelope_iv[EVP_MAX_IV_LENGTH];
    // unsigned char *envelope_iv = NULL;
    unsigned char **encrypted_envelope_keys = malloc(1 * sizeof(unsigned char *));
    // unsigned char encrypted_envelope_keys[1][128]
    int encrypted_envelope_key_len[1] = {0};
    //unsigned char *key_mat;

    /* I'm not sure about this buffer size... got it by printing it out when
    running code... should probably be doing things better :'(
    Also, note that unsigned chars are used in various places, but this buffer
    is a char?!??!

    HACK The size of this buffer should be different...
    It is dangerous right now and we risk overflowing later on...
    */
    char temp_buff[21848] = {0};
    
    if (s->state == SPP_ST_CW_PRXY_MAT_A) {

        // Pack the message into the temp buffer
        p=d=&(temp_buff[0]);
        n = 0;
        for (i = 0; i < proxy->read_slice_ids_len; i++) {
            slice = SPP_get_slice_by_id(s, proxy->read_slice_ids[i]);
            if (slice == NULL)
                goto err;
            
            s1n(slice->slice_id, p);
            s2n(EVP_MAX_KEY_LENGTH, p);
            memcpy(p, slice->read_mat, EVP_MAX_KEY_LENGTH);
            p += EVP_MAX_KEY_LENGTH;
            
            found = 0;
            for (j = 0; j < proxy->write_slice_ids_len; j++) {
                if (proxy->write_slice_ids[j] == slice->slice_id) {
                    found=1;
                    break;
                }
            }
            // Write permission, so add the write key
            if (found) {
                s2n(EVP_MAX_KEY_LENGTH, p);
                memcpy(p, slice->write_mat, EVP_MAX_KEY_LENGTH);
                p += EVP_MAX_KEY_LENGTH;
            } else {
                // No write permission, write a 0
                s2n(0, p);
            }
        }
        n = p-d;

        /* Encrypt using envelopes. What this means is that the data we are
        sending will be encrypted with a randomly generated shared secret key.
        The shared secret key is then encrypted via the RSA pub key of the
        destination.
        */
       
        d = (unsigned char *)s->init_buf->data;
        p = &(d[4]);

        /* Need to free this later on still */
        //key_mat = malloc(n * sizeof(unsigned char *));
        
        //pub_key = X509_get_pubkey(SSL_get_peer_certificate(s));
        pub_key = X509_get_pubkey(proxy->peer);
        pub_keys[0] = pub_key;

        encrypted_envelope_keys[0] = malloc(RSA_size(pub_keys[0]->pkey.rsa));


        memset(envelope_iv, 0, sizeof envelope_iv);  /* per RFC 1510 */

        /* seal the envelope */
        encrypted_key_mat_len = envelope_seal(
            pub_keys,
            temp_buff,
            n,
            encrypted_envelope_keys,
            &encrypted_envelope_key_len,
            envelope_iv,
            encrypted_key_mat,
            shared_secret);

        /* store the shared secret */
        memcpy(s->proxy_key_mat_shared_secret, shared_secret, sizeof(shared_secret));


        *(d++)=SPP_MT_PROXY_KEY_MATERIAL;


        /* calculate the size of the payload */
        n = 4; /* to store length of encrypted envelope key and destination ID*/
        n += encrypted_envelope_key_len[0]; /* to store the encrypted envelope key */
        n += EVP_MAX_IV_LENGTH; /* to store the iv */
        n += 3; /* to store the length of the encrypted data */
        n += encrypted_key_mat_len; /* to store the encrypted key material */

        // printf("total legnth of message: %d\n", n);
        l2n3(n,d);

        //p = &(((unsigned char *)s->init_buf->data)[4]);
        // p = &(d[4]);

        /* If we are server, we send to client (1), otherwise we send to server (2)*/
        s1n(proxy->proxy_id, d);
        
        /* Now we need to handle writing encryption stuff! */

        /* write the length of the encrypted key */
        l2n3(encrypted_envelope_key_len[0], d);
        // l2n3(1, d);


        /* write the encrypted envelope key */
        memcpy(d, encrypted_envelope_keys[0], encrypted_envelope_key_len[0]);
        /* free the allocated mem */
        free(encrypted_envelope_keys[0]);

        /* advance pointer! */
        d += encrypted_envelope_key_len[0];

        memcpy(d, envelope_iv, EVP_MAX_IV_LENGTH);

        /* advance pointer */
        d += EVP_MAX_IV_LENGTH;

        /* write the legnth of encrypted key material */
        l2n3(encrypted_key_mat_len, d);

        /* write the encrypted key material */

        memcpy(d, encrypted_key_mat, encrypted_key_mat_len);

        /* advance pointer! */
        d += encrypted_key_mat_len;

        // printf("after copying relevant stuff (is %d bytes)...\n", n);
        // spp_print_buffer(p, n);


        // memcpy(&(d2[4]), temp_buff, n);

        s->state=SPP_ST_CW_PRXY_MAT_B;
        /* number of bytes to write */

        /*
        Here we should realy ensure that we are writing the size of the
        encrypted key material
        */
        s->init_num=n+4;
        s->init_off=0;

        printf("Sending proxy key material, n=%d\n", n);
        spp_print_buffer((unsigned char *)s->init_buf->data, s->init_num);
    }

    /* SPP_ST_CW_PRXY_MAT_B */
    return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
err:
    printf("Error sending proxy key material\n");
    return(-1);
}

int spp_send_end_key_material_client(SSL *s) {

    EVP_PKEY *pub_key = NULL;
    EVP_PKEY **pub_keys = malloc(1 * sizeof(EVP_PKEY *));
    unsigned char shared_secret[EVP_MAX_KEY_LENGTH];
    // unsigned char *encrypted_key_mat = NULL;
    /* THIS PROBABLY NEEDS TO BE CHANGED TO BE MORE DYNAMIC AND HAVE THE REAL LENGTH*/
    unsigned char encrypted_key_mat[1024];
    int encrypted_key_mat_len = 0; //[1] = {0};
    unsigned char envelope_iv[EVP_MAX_IV_LENGTH];
    // unsigned char *envelope_iv = NULL;
    unsigned char **encrypted_envelope_keys = malloc(1 * sizeof(unsigned char *));
    // unsigned char encrypted_envelope_keys[1][128]
    int encrypted_envelope_key_len[1] = {0};
    unsigned char *p,*d;
    int n;

    /* I'm not sure about this buffer size... got it by printing it out when
    running code... should probably be doing things better :'(
    Also, note that unsigned chars are used in various places, but this buffer
    is a char?!??!

    HACK The size of this buffer should be different...
    It is dangerous right now and we risk overflowing later on...
    */
    char temp_buff[21848] = {0};

    
    if (s->state == SPP_ST_CW_PRXY_MAT_A) {

        n = spp_pack_proxy_key_mat(s, temp_buff);

        /* Encrypt using envelopes. What this means is that the data we are
        sending will be encrypted with a randomly generated shared secret key.
        The shared secret key is then encrypted via the RSA pub key of the
        destination.
        */
       
        d = (unsigned char *)s->init_buf->data;
        p = &(d[4]);

        /* Need to free this later on still */
        //key_mat = malloc(n * sizeof(unsigned char *));

        pub_key = X509_get_pubkey(SSL_get_peer_certificate(s));
        pub_keys[0] = pub_key;

        encrypted_envelope_keys[0] = malloc(RSA_size(pub_keys[0]->pkey.rsa));


        memset(envelope_iv, 0, sizeof envelope_iv);  /* per RFC 1510 */

        /* seal the envelope */
        encrypted_key_mat_len = envelope_seal(
            pub_keys,
            temp_buff,
            n,
            encrypted_envelope_keys,
            &encrypted_envelope_key_len,
            envelope_iv,
            encrypted_key_mat,
            shared_secret);

        /* store the shared secret */
        memcpy(s->proxy_key_mat_shared_secret, shared_secret, sizeof(shared_secret));




        *(d++)=SPP_MT_PROXY_KEY_MATERIAL;


        /* calculate the size of the payload */
        n = 4; /* to store length of encrypted envelope key and destination ID*/
        n += encrypted_envelope_key_len[0]; /* to store the encrypted envelope key */
        n += EVP_MAX_IV_LENGTH; /* to store the iv */
        n += 3; /* to store the length of the encrypted data */
        n += encrypted_key_mat_len; /* to store the encrypted key material */

        // printf("total legnth of message: %d\n", n);
        l2n3(n,d);

        //p = &(((unsigned char *)s->init_buf->data)[4]);
        // p = &(d[4]);

        /* If we are server, we send to client (1), otherwise we send to server (2)*/
        s1n(s->server == 0 ? 2 : 1, d);
        
        /* Now we need to handle writing encryption stuff! */

        /* write the length of the encrypted key */
        l2n3(encrypted_envelope_key_len[0], d);
        // l2n3(1, d);


        /* write the encrypted envelope key */
        memcpy(d, encrypted_envelope_keys[0], encrypted_envelope_key_len[0]);
        /* free the allocated mem */
        free(encrypted_envelope_keys[0]);

        /* advance pointer! */
        d += encrypted_envelope_key_len[0];

        memcpy(d, envelope_iv, EVP_MAX_IV_LENGTH);

        /* advance pointer */
        d += EVP_MAX_IV_LENGTH;

        /* write the legnth of encrypted key material */
        l2n3(encrypted_key_mat_len, d);

        /* write the encrypted key material */

        memcpy(d, encrypted_key_mat, encrypted_key_mat_len);

        /* advance pointer! */
        d += encrypted_key_mat_len;

        // printf("after copying relevant stuff (is %d bytes)...\n", n);
        // spp_print_buffer(p, n);


        // memcpy(&(d2[4]), temp_buff, n);

        s->state=SPP_ST_CW_PRXY_MAT_B;
        /* number of bytes to write */

        /*
        Here we should realy ensure that we are writing the size of the
        encrypted key material
        */
        s->init_num=n+4;
        s->init_off=0;

        printf("Sending end key material, n=%d\n", n);
        spp_print_buffer((unsigned char *)s->init_buf->data, s->init_num);
    }

    /* SPP_ST_CW_PRXY_MAT_B */
    return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
err:
    return(-1);
}

int spp_send_end_key_material_server(SSL *s) {
    unsigned char *p,*d;
    int n;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char encrypted_key_mat[2048];
    int encrypted_key_mat_len = 0;
    char temp_buff[21848] = {0};

    if (s->state == SPP_ST_CW_PRXY_MAT_A) {
        n = spp_pack_proxy_key_mat(s, temp_buff);

        /* 0 out per some rfc.
        iv is randomized in spp_encrypt_key_mat_server()
        */
        memset(iv, 0, EVP_MAX_IV_LENGTH);

        printf("Proxy key material shared secret (server):\n");
        spp_print_buffer(s->proxy_key_mat_shared_secret, EVP_MAX_KEY_LENGTH);

        encrypted_key_mat_len = spp_encrypt_key_mat_server(
            s->proxy_key_mat_shared_secret,
            EVP_MAX_KEY_LENGTH,
            iv,
            temp_buff,
            n,
            encrypted_key_mat
            );

        printf("server->client key material:\n");
        spp_print_buffer(temp_buff, n);
        printf("server->client encrypted_key_mat:\n");
        spp_print_buffer(encrypted_key_mat, encrypted_key_mat_len);

        d = (unsigned char *)s->init_buf->data;
        p = &(d[4]);

        /* Now we need to copy relevant info into the full buffer */
        n = encrypted_key_mat_len+1; /* the actual encrypted key material and 1 byte for the proxy_id*/
        n += 3; /* for the length of the encrypted key material */
        n += 3; /* for the length of the iv */
        n += EVP_MAX_IV_LENGTH; /* for the length of the iv HACK: This should be dynamic? */

        s1n(s->server == 0 ? 2 : 1, p);
        
        /* copy in the length of the encrypted key material */
        l2n3(encrypted_key_mat_len, p);

        /* copy in the encrypted key material */
        memcpy(p, encrypted_key_mat, encrypted_key_mat_len);
        /* advance pointer */
        p += encrypted_key_mat_len;

        /* copy in the length of the iv */
        l2n3(EVP_MAX_IV_LENGTH, p);

        /* copy in the actual iv */
        memcpy(p, iv, EVP_MAX_IV_LENGTH);


        *(d++)=SPP_MT_PROXY_KEY_MATERIAL;
        l2n3(n,d);

        s->state=SPP_ST_CW_PRXY_MAT_B;
        /* number of bytes to write */
        s->init_num=n+4;
        s->init_off=0;

        printf("Sending end key material, n=%d\n", n);
        spp_print_buffer((unsigned char *)s->init_buf->data, s->init_num);
    }

    /* SPP_ST_CW_PRXY_MAT_B */
    return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
err:
    return(-1);
}

int spp_send_end_key_material(SSL *s) {
    unsigned char *p,*d;
    int n,i;

    if (s->state == SPP_ST_CW_PRXY_MAT_A) {
        d=(unsigned char *)s->init_buf->data;
        p= &(d[4]);
        
        n = 0;
        s1n(s->server == 0 ? 2 : 1, p);
        for (i = 0; i < s->slices_len; i++) {
            s1n(s->slices[i]->slice_id, p);
            s2n(EVP_MAX_KEY_LENGTH, p);    
            memcpy(p, s->slices[i]->read_mat, EVP_MAX_KEY_LENGTH);
            p += EVP_MAX_KEY_LENGTH;
            s2n(EVP_MAX_KEY_LENGTH, p);    
            memcpy(p, s->slices[i]->write_mat, EVP_MAX_KEY_LENGTH);
            p += EVP_MAX_KEY_LENGTH;
        }
        n = p-d-4;

        /* Encrypt using the master key previously negotiated. */
        /*if ((cipher=OPENSSL_malloc(sizeof(EVP_CIPHER_CTX))) == NULL)
            goto err;
        EVP_CIPHER_CTX_init(cipher);

        if(!EVP_EncryptInit_ex(cipher, c, NULL, s->session->master_key, aesIV)) {
             goto err;
        }*/

        *(d++)=SPP_MT_PROXY_KEY_MATERIAL;
        l2n3(n,d);

        s->state=SPP_ST_CW_PRXY_MAT_B;
        /* number of bytes to write */
        s->init_num=n+4;
        s->init_off=0;

#ifdef DEBUG
        printf("Sending end key material, n=%d\n", n);
        spp_print_buffer((unsigned char *)s->init_buf->data, s->init_num);
#endif
    }

    /* SPP_ST_CW_PRXY_MAT_B */
    return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
}

int spp_get_end_key_material_client(SSL *s) {

    unsigned char key_mat[21848] = {0};
    unsigned char encrypted_key_mat[21848] = {0};
    int encrypted_key_mat_len, key_mat_len = 0;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    int iv_len = 0;
    unsigned char *param,*p;
    int ok;
    long n;
    int id;

    n=s->method->ssl_get_message(s,
        SPP_ST_CR_PRXY_MAT_A,
        SPP_ST_CR_PRXY_MAT_B,
        SPP_MT_PROXY_KEY_MATERIAL,
        SSL3_RT_MAX_PLAIN_LENGTH,
        &ok);
    if (!ok) return((int)n);

    /* unpack our data */
    p = (unsigned char*)s->init_msg;
    
    /* Get the ID */
    n1s(p, id);
    if (id != 1) {
        /* Material not intended for client */
        return -1;
    }
    
    /* encrypted key mat len */
    n2l3(p, encrypted_key_mat_len);

    /* get the encrypted key material */
    memcpy(encrypted_key_mat, p, encrypted_key_mat_len);
    // printf("client get key material, encrypted key mat:\n");
    // spp_print_buffer(encrypted_key_mat, encrypted_key_mat_len);
    /* advance pointer */
    p += encrypted_key_mat_len;

    /* get the length of the iv */
    n2l3(p, iv_len);

    /* get the iv itself */
    memcpy(iv, p, iv_len);

    printf("Proxy key material shared secret (client):\n");
    spp_print_buffer(s->proxy_key_mat_shared_secret, EVP_MAX_KEY_LENGTH);

    /* decrypt the key material */
    key_mat_len = spp_decrypt_key_mat_client(
        s->proxy_key_mat_shared_secret,
        EVP_MAX_KEY_LENGTH,
        iv,
        encrypted_key_mat,
        encrypted_key_mat_len,
        key_mat);
    printf("key mat len: %d\n", key_mat_len);
    printf("client get key material, key mat:\n");
    spp_print_buffer(key_mat, key_mat_len);
    
    return spp_unpack_proxy_key_mat(s, key_mat, key_mat_len);
}

int spp_get_end_key_material_server(SSL *s) {

    unsigned char key_mat[1024] = {0};
    int *key_mat_len = 0;
    EVP_PKEY *private_key = NULL;
    unsigned char *key_mat_envelope = NULL;
    int encrypted_envelope_key_len = 0;
    unsigned char envelope_iv[EVP_MAX_IV_LENGTH];
    unsigned char encrypted_envelope_key[128] = {0};
    int encrypted_key_mat_len = 0;
    unsigned char encrypted_key_mat[2048]; /* HACK size... */
    int ok,id;
    long n;

    n=s->method->ssl_get_message(s,
        SPP_ST_CR_PRXY_MAT_A,
        SPP_ST_CR_PRXY_MAT_B,
        SPP_MT_PROXY_KEY_MATERIAL,
        SSL3_RT_MAX_PLAIN_LENGTH,
        &ok);
    if (!ok) return((int)n);

    // printf("length of msg received by server: %d\n", n);

    /* we need to decrypt the message first... */
    // printf("getting private key\n");
    private_key = s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey; 

    key_mat_envelope = (unsigned char *)s->init_msg;
    // printf("Payload from client:\n");
    // spp_print_buffer(key_mat_envelope, n);
    
    /* Get the ID */
    n1s(key_mat_envelope, id);
    if (id != 2) {
        /* Material not intended for server */
        return -1;
    }

    /* get length of encrypted envelope key */
    n2l3(key_mat_envelope, encrypted_envelope_key_len);
    

    /* now pull out the encrypted envelope key */
    memcpy(encrypted_envelope_key, key_mat_envelope, encrypted_envelope_key_len); // );
    // printf("encrypted envelope key:\n");
    // spp_print_buffer(encrypted_envelope_key, encrypted_envelope_key_len);

    /* advance pointer! */
    key_mat_envelope += encrypted_envelope_key_len;

    /* read iv */
    // printf("reading iv\n");
    memcpy(envelope_iv, key_mat_envelope, EVP_MAX_IV_LENGTH);
    // printf("envelope_iv:\n");
    // // printf("%s\n", envelope_iv);
    // spp_print_buffer(envelope_iv, EVP_MAX_IV_LENGTH);
    /* advance pointer! */
    key_mat_envelope += EVP_MAX_IV_LENGTH;

    /* get legnth of encrypted key material */
    n2l3(key_mat_envelope, encrypted_key_mat_len);

    /* pull the encrypted key material out! */
    memcpy(encrypted_key_mat, key_mat_envelope, encrypted_key_mat_len);
    // printf("Encrypted key material:\n");
    // spp_print_buffer(encrypted_key_mat, encrypted_key_mat_len);

    printf("opening envelope!\n");

    key_mat_len = envelope_open(
        private_key,
        encrypted_key_mat,
        encrypted_key_mat_len,
        encrypted_envelope_key,
        encrypted_envelope_key_len,
        envelope_iv,
        key_mat,
        s->proxy_key_mat_shared_secret
        );

    // printf("key mat len: %d\n", key_mat_len);
    // spp_print_buffer(key_mat, key_mat_len);

    /* if we are lucky, key_mat conatins the unencrypted key material! */
    return spp_unpack_proxy_key_mat(s, key_mat, key_mat_len);
}

/* Old method to be removed. This is an unencrypted proxykeymat */
int spp_get_end_key_material(SSL *s) { 
    unsigned char *param,*p;
    int ok;
    long n;
    int id,slice_id,len;
    SPP_SLICE *slice;

    n=s->method->ssl_get_message(s,
        SPP_ST_CR_PRXY_MAT_A,
        SPP_ST_CR_PRXY_MAT_B,
        SPP_MT_PROXY_KEY_MATERIAL,
        SSL3_RT_MAX_PLAIN_LENGTH,
        &ok);
    if (!ok) return((int)n);

    param=p=(unsigned char *)s->init_msg;
    /* Server or client identifier */
    //printf("Message header %d, %d, %d, %d\n", p[0], p[1], p[2], p[3]);
    n1s(p, id);
    if (id != 1 && id != 2) {
        goto err;
    }
    
    /* More to read */
    while (p-param < n) {
        n1s(p, slice_id);
        //printf("Slice %d received\n", slice_id);
        slice = SPP_get_slice_by_id(s, slice_id);
        if (slice == NULL)            
            goto err;
        
        n2s(p, len);
        if (len > EVP_MAX_KEY_LENGTH)
            goto err;        
        memcpy(slice->other_read_mat, p, len);
        p += len;
        
        n2s(p, len);
        if (len > EVP_MAX_KEY_LENGTH)
            goto err;
        memcpy(slice->other_write_mat, p, len);
        p += len;
        
        slice->write_access = 1;
        slice->read_access = 1;        
    }
    /* Should now have read the full message. */
    if (p-param != n) {
        printf("Did not read the whole message, %d != %d\n", (int)(p-param), n);
        goto err;
    }
    /* Check to make sure we have material for all slices. 
     * and generate the contexts. */
    for (n = 0; n < s->slices_len; n++) {
        if (s->slices[n]->write_access == 0 || s->slices[n]->read_access == 0) {
            printf("Slice %d missing\n", s->slices[n]->slice_id);
            goto err;
        }
        
        /* Do not init yet. Save this for on sending the change cipher state message. */
        /*if (spp_init_slice_st(s, s->slices[n]) <= 0) {
            printf("Slice %d init failure\n", s->slices[n]->slice_id);
            goto err;
        }*/
    }
    
    return 1;
err:
    return(-1);
}

/* Open an envelope.
Also return the shared secret key!

TODO Proper error handling
*/
int envelope_open(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
    unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
    unsigned char *plaintext, unsigned char *shared_secret_key)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;


    /* Create and initialise the context */
    printf("Create and initialise the context\n");
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        // handleErrors();
        printf("envelope_open error 1\n");
    }

    printf("Initialise the decryption operation.\n");
    /* Initialise the decryption operation. The asymmetric private key is
     * provided and priv_key, whilst the encrypted session key is held in
     * encrypted_key */
    if(1 != spp_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key,
        encrypted_key_len, iv, priv_key, shared_secret_key)) {
        //handleErrors();
        printf("envelope_open error 2\n");
    }
        

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_OpenUpdate can be called multiple times if necessary
     */
    // printf("Provide the message to be decrypted, and obtain the plaintext output.\n");
    if(1 != EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        // handleErrors();
        printf("envelope_open error 3\n");
    }
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
     // printf("Finalise the decryption.\n");
    if(1 != EVP_OpenFinal(ctx, plaintext + len, &len)) {
        // handleErrors();
        printf("envelope_open error 4\n");
    }
    plaintext_len += len;

    /* Clean up */
    // printf("clean up\n");
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

/*
Create an envelope, encrypt with pub key, etc...
Also returns the shared secret key.

TODO Proper error handling
*/
int envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len,
    unsigned char **encrypted_key, int *encrypted_key_len, unsigned char *iv,
    unsigned char *ciphertext, unsigned char *shared_secret_key)
{
    EVP_CIPHER_CTX *ctx;

    int ciphertext_len;

    // unsigned char *ek;

    int len;




    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) printf("ERROR\n");//handleErrors();
    // ek = malloc(EVP_PKEY_size(pub_key));

    /* Initialise the envelope seal operation. This operation generates
     * a key for the provided cipher, and then encrypts that key a number
     * of times (one for each public key provided in the pub_key array). In
     * this example the array size is just one. This operation also
     * generates an IV and places it in iv. */
     // printf("Running SealInit\n");
    if(1 != spp_SealInit(ctx, EVP_aes_256_cbc(), encrypted_key, encrypted_key_len, iv, pub_key, 1, shared_secret_key)) {
        printf("ERROR2\n");
        // handleErrors();
    }
    
        

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_SealUpdate can be called multiple times if necessary
     */
    if(1 != EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        printf("ERROR3\n");
        // handleErrors();
    }
        

    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_SealFinal(ctx, ciphertext + len, &len)) {
        printf("ERROR4\n");
        // handleErrors();
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/*
HACK Custom version of EVP_OpenInit that also returns the shared secret key.

TODO Proper error handling
*/

int spp_OpenInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
    const unsigned char *ek, int ekl, const unsigned char *iv,
    EVP_PKEY *priv, unsigned char *shared_secret)
    {
    unsigned char *key=NULL;
    int i,size=0,ret=0;

    if(type) {  
        EVP_CIPHER_CTX_init(ctx);
        if(!EVP_DecryptInit_ex(ctx,type,NULL, NULL,NULL)) 
            {
                printf("what's up?\n");
                return 0;
            }
    }

    if(!priv) return 1;

    if (priv->type != EVP_PKEY_RSA) {
        EVPerr(EVP_F_EVP_OPENINIT,EVP_R_PUBLIC_KEY_NOT_RSA);
        goto err;
    }

    size=RSA_size(priv->pkey.rsa);
    key=(unsigned char *)OPENSSL_malloc(size+2);
    if (key == NULL)
        {
        /* ERROR */
        EVPerr(EVP_F_EVP_OPENINIT,ERR_R_MALLOC_FAILURE);
        goto err;
        }

    i=EVP_PKEY_decrypt_old(key,ek,ekl,priv);
    memcpy(shared_secret, key, (size + 2));
    if ((i <= 0) || !EVP_CIPHER_CTX_set_key_length(ctx, i)) {
        /* ERROR */
        goto err;
    }
    if(!EVP_DecryptInit_ex(ctx,NULL,NULL,key,iv)) goto err;

    ret=1;
err:
    if (key != NULL) OPENSSL_cleanse(key,size);

    /* Before we free the key, let's copy it out to the shared_secret... */

    OPENSSL_free(key);
    return(ret);
    }


/* TODO Proper error handling */
int spp_decrypt_key_mat_client(
    unsigned char *symmetric_key,
    int symmetric_key_len,
    unsigned char *iv,
    unsigned char *cipher_text,
    int cipher_text_len,
    unsigned char *plain_text) {

    EVP_CIPHER_CTX *ctx;

    EVP_CIPHER *type = EVP_aes_256_cbc();

    int plain_text_len;

    int len;

    if (!(ctx = EVP_CIPHER_CTX_new())) printf("ERROR1\n");

    if (type) {
        EVP_CIPHER_CTX_init(ctx);
        if (!EVP_DecryptInit_ex(ctx, type, NULL, symmetric_key, iv)) return 0;
    }

    if (1 != EVP_DecryptUpdate(ctx, plain_text, &len, cipher_text, cipher_text_len)) {
        printf("ERROR2\n");
    }

    plain_text_len = len;

    /* finalize decrpytion */
    int i;
    i = EVP_DecryptFinal_ex(ctx, plain_text + len, &len);
    if (i) {
        i = EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, NULL);
    }

    plain_text_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plain_text_len;

}

/* TODO Proper error handling */
int spp_encrypt_key_mat_server(

    unsigned char *symmetric_key,
    int symmetric_key_len,
    unsigned char *iv,
    unsigned char *plain_text,
    int plain_text_len,
    unsigned char *cipher_text) {

    EVP_CIPHER_CTX *ctx;

    EVP_CIPHER *type = EVP_aes_256_cbc();

    int ciphertext_len;

    

    // unsigned char *ek;

    int len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) printf("ERROR\n");//handleErrors();
    if(type) {
        EVP_CIPHER_CTX_init(ctx);

        /* gotta initialize the context properly i guess */

        if(!EVP_EncryptInit_ex(ctx,type,NULL,NULL,NULL)) return 0;
    }

    /* generate random iv */
    if (EVP_CIPHER_CTX_iv_length(ctx)) {
        RAND_pseudo_bytes(iv,EVP_CIPHER_CTX_iv_length(ctx));
    }

    if(!EVP_EncryptInit_ex(ctx,type,NULL,symmetric_key,iv)) return 0;

    if(1 != EVP_EncryptUpdate(ctx, cipher_text, &len, plain_text, plain_text_len)) {
        printf("ERROR3\n");
        // handleErrors();
    }

    // Finalize

    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    int i;
    i = EVP_EncryptFinal_ex(ctx,cipher_text + len, &len);
    if (i) 
        i = EVP_EncryptInit_ex(ctx,NULL,NULL,NULL,NULL);
    if (1 != i) {
        printf("ERROR4\n");
    }

    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
/*
HACK
Custom version of EVP_SealInit that also returns the shared secret key that's
generated.

HACK NO IDEA IF REUSING THE SHARED SECRET KEY LATER ON COMPROMISES THE INTEGRITY
OF THE ENCRYPTION ALGORITHM!!!!!!
*/
int spp_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, unsigned char **ek,
         int *ekl, unsigned char *iv, EVP_PKEY **pubk, int npubk, unsigned char *key)
    {
    // unsigned char key[EVP_MAX_KEY_LENGTH];
    int i;

    //
    BIO *bio_out = NULL;
    //
    
    if(type) {
        EVP_CIPHER_CTX_init(ctx);
        if(!EVP_EncryptInit_ex(ctx,type,NULL,NULL,NULL)) return 0;
    }
    if ((npubk <= 0) || !pubk)
        return 1;
    if (EVP_CIPHER_CTX_rand_key(ctx, key) <= 0)
        return 0;
    if (EVP_CIPHER_CTX_iv_length(ctx))
        RAND_pseudo_bytes(iv,EVP_CIPHER_CTX_iv_length(ctx));

    if(!EVP_EncryptInit_ex(ctx,NULL,NULL,key,iv)) return 0;


    for (i=0; i<npubk; i++)
    {
        // printf("public key %d is %d bits\n", i, EVP_PKEY_bits(pubk[i]));
        // printf("pubk[i]-type: %d\n", pubk[i]->type);
        // printf("ekl[i] = %d\n", ekl[i]);
        // printf("Public key:\n");
        // bio_out = BIO_new_fp(stdout,BIO_NOCLOSE);
        // printf("Key: %s\n", key);
        // EVP_PKEY_print_public(bio_out, pubk[i], 4, NULL);

        ekl[i]=EVP_PKEY_encrypt_old(ek[i],key,EVP_CIPHER_CTX_key_length(ctx),
            pubk[i]);
        if (ekl[i] <= 0) return(-1);
    }
    return(npubk);
}

int spp_unpack_proxy_key_mat(SSL *s, unsigned char *p, long n) {
    int len, slice_id;
    SPP_SLICE *slice;
    unsigned char *param=p;
    
    /* More to read */
    while (p-param < n) {
        n1s(p, slice_id);
        //printf("Slice %d received\n", slice_id);
        slice = SPP_get_slice_by_id(s, slice_id);
        if (slice == NULL) {        
            printf("Invalid slice id: %d\n", slice_id);
            goto err;
        }
        
        n2s(p, len);
        if (len > EVP_MAX_KEY_LENGTH)
            goto err;        
        memcpy(slice->other_read_mat, p, len);
        p += len;
        
        n2s(p, len);
        if (len > EVP_MAX_KEY_LENGTH)
            goto err;
        memcpy(slice->other_write_mat, p, len);
        p += len;
        
        slice->write_access = 1;
        slice->read_access = 1;        
    }
    /* Should now have read the full message. */
    if (p-param != n) {
        printf("Did not read the whole message, %d != %d\n", p-param, n);
        goto err;
    }
    /* Check to make sure we have material for all slices. 
     * and generate the contexts. */
    for (n = 0; n < s->slices_len; n++) {
        if (s->slices[n]->write_access == 0 || s->slices[n]->read_access == 0) {
            printf("Slice %d missing\n", s->slices[n]->slice_id);
            goto err;
        }
        
        /* Do not init yet. Save this for on sending the change cipher state message. */
        /*if (spp_init_slice_st(s, s->slices[n]) <= 0) {
            printf("Slice %d init failure\n", s->slices[n]->slice_id);
            goto err;
        }*/
    }
    return 1;
err:
    printf("Error in unpacking key material\n");
    return -1;
}

/* TODO Make this work and use it in spp_send_end_key_material_client/server !*/
int spp_pack_proxy_key_mat(SSL *s, unsigned char *proxy_key_mat) {
    int n, i = 0;
    unsigned char *p, *d;

    /* I'm not sure about this buffer size... got it by printing it out when
    running code... should probably be doing things better :'(
    Also, note that unsigned chars are used in various places, but this buffer
    is a char?!??!

    HACK The size of this buffer should be different...
    It is dangerous right now and we risk overflowing later on...
    */
    // char temp_buff[21848] = {0};

    /* NOTE: data in the init_buf is really a char?!?! s->init_buf->data; */
    d=(unsigned char *)proxy_key_mat;
    // p= &(d[4]);
    // p= &(d[0]);
    p = d;

    n = 0;

    for (i = 0; i < s->slices_len; i++) {
        s1n(s->slices[i]->slice_id, p);
        s2n(EVP_MAX_KEY_LENGTH, p);
        memcpy(p, s->slices[i]->read_mat, EVP_MAX_KEY_LENGTH);
        p += EVP_MAX_KEY_LENGTH;
        s2n(EVP_MAX_KEY_LENGTH, p);    
        memcpy(p, s->slices[i]->write_mat, EVP_MAX_KEY_LENGTH);
        p += EVP_MAX_KEY_LENGTH;
    }
    // n = p-d -4;
    n = p - d;
    return n;
}

void spp_print_buffer(unsigned char *buf, int len) {
    printf("(%d) ", len);
    while (len-- > 0) {
        if (len == 0)
            printf("%x",(*(buf++))&0xff);
        else
            printf("%x:",(*(buf++))&0xff);
    }
    printf("\n");
}

long spp_get_message(SSL *s, int st1, int stn, int mt, long max, int *ok) {
    int ret;
    ret=ssl3_get_message(s, st1, stn, mt, max, ok);
    // Received a full message as a proxy
    /*if (s->proxy && *ok) {
        // Received message was a client hello, special case
        // Cannot forward on a client hello until after state initialization.
        if (mt != SSL3_MT_CLIENT_HELLO) {
            
        }
        // Forward client hello on.
                if ((address = spp_process_clienthello(s)) == NULL)
                    goto end;
                if ((next_st = s->proxy_func(s, address)) == NULL)
                    goto end;
                s->other_ssl = next_st;
                next_st->other_ssl = s;
    }*/
    return ret;
}