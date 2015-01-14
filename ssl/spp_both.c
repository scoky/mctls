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

    if (s->state == SPP_ST_CW_PRXY_MAT_A) {
        d=(unsigned char *)s->init_buf->data;
        p= &(d[4]);
        
        n = 0;
        s1n(proxy->proxy_id, p);
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
        n = p-d-4;
        
        *(d++)=SPP_MT_PROXY_KEY_MATERIAL;
        l2n3(n,d);

        s->state=SPP_ST_CW_PRXY_MAT_B;
        /* number of bytes to write */
        s->init_num=n+4;
        s->init_off=0;
        
#ifdef DEBUG
        printf("Sending proxy key material\n");
        spp_print_buffer((unsigned char *)s->init_buf->data, s->init_num);
#endif
    }

    /* SPP_ST_CW_PRXY_MAT_B */
    return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
err:
    printf("Error sending proxy key material\n");
    return(-1);
}

int spp_send_end_key_material(SSL *s) {
    unsigned char *p,*d;
    int n,i;
    unsigned long alg_k;
    const EVP_CIPHER *c;
#ifndef OPENSSL_NO_ECDH
    EC_KEY *clnt_ecdh = NULL;
    const EC_POINT *srvr_ecpoint = NULL;
    EVP_PKEY *srvr_pub_pkey = NULL;
    unsigned char *encodedPoint = NULL;
    int encoded_pt_len = 0;
    BN_CTX * bn_ctx = NULL;
#endif
    const EVP_MD *m;
    EVP_MD_CTX md;
    EVP_CIPHER_CTX *cipher;
    
    int is_exp;
    struct sess_cert_st /* SESS_CERT */ *sess_cert;

    is_exp=SSL_C_IS_EXPORT(s->s3->tmp.new_cipher);
    c=s->s3->tmp.new_sym_enc;
    m=s->s3->tmp.new_hash;

    if (s->state == SPP_ST_CW_PRXY_MAT_A) {
        d=(unsigned char *)s->init_buf->data;
        p= &(d[4]);

        alg_k=s->s3->tmp.new_cipher->algorithm_mkey;

        sess_cert = s->session->sess_cert;
        
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
err:
    return(-1);
}

int spp_get_end_key_material(SSL *s) { 
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
    EC_KEY *clnt_ecdh = NULL;
    EVP_PKEY *srvr_pub_pkey = NULL;
    unsigned char *encodedPoint = NULL;
#endif
    int id,slice_id,len;
    SPP_SLICE *slice;
    struct sess_cert_st /* SESS_CERT */ *sess_cert;

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
    return(-1);
}

void spp_print_buffer(unsigned char *buf, int len) {
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