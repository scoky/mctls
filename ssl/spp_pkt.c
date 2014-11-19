#include <stdio.h>
#include <limits.h>
#include <errno.h>
#define USE_SOCKETS
#include "ssl_locl.h"
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>

#define MAX_EMPTY_RECORDS 10 /* Might not be needed */
static int spp_get_record(SSL *s)
	{
	int ssl_major,ssl_minor,al;
	int enc_err,n,i,ret= -1;
	SSL3_RECORD *rr;
	SSL_SESSION *sess;
	unsigned char *p;
	unsigned char md[EVP_MAX_MD_SIZE];
	short version;
	unsigned mac_size, orig_len;
	size_t extra;
	unsigned empty_record_count = 0;

	rr= &(s->s3->rrec);
	sess=s->session;

	if (s->options & SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER)
		extra=SSL3_RT_MAX_EXTRA;
	else
		extra=0;
	if (extra && !s->s3->init_extra)
		{
		/* An application error: SLS_OP_MICROSOFT_BIG_SSLV3_BUFFER
		 * set after ssl3_setup_buffers() was done */
		SSLerr(SSL_F_SSL3_GET_RECORD, ERR_R_INTERNAL_ERROR);
		return -1;
		}

again:
	/* check if we have the header */
	if (	(s->rstate != SSL_ST_READ_BODY) ||
		(s->packet_length < SSL3_RT_HEADER_LENGTH)) 
		{
		n=ssl3_read_n(s, SSL3_RT_HEADER_LENGTH, s->s3->rbuf.len, 0);
		if (n <= 0) return(n); /* error or non-blocking */
		s->rstate=SSL_ST_READ_BODY;

		p=s->packet;

		/* Pull apart the header into the SSL3_RECORD */
		rr->type= *(p++);
		ssl_major= *(p++);
		ssl_minor= *(p++);
		version=(ssl_major<<8)|ssl_minor;
                /* New header field: slice_id */
                rr->slice_id = *(p++);
		n2s(p,rr->length);
#if 0
fprintf(stderr, "Record type=%d, Length=%d\n", rr->type, rr->length);
#endif

		/* Lets check version */
		if (!s->first_packet)
			{
			if (version != s->version)
				{
				SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_WRONG_VERSION_NUMBER);
                                if ((s->version & 0xFF00) == (version & 0xFF00) && !s->enc_write_ctx && !s->write_hash)
                                	/* Send back error using their minor version number :-) */
					s->version = (unsigned short)version;
				al=SSL_AD_PROTOCOL_VERSION;
				goto f_err;
				}
			}

		if ((version>>8) != SPP_VERSION_MAJOR)
			{
			SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_WRONG_VERSION_NUMBER);
			goto err;
			}

		if (rr->length > s->s3->rbuf.len - SPP_RT_HEADER_LENGTH)
			{
			al=SSL_AD_RECORD_OVERFLOW;
			SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_PACKET_LENGTH_TOO_LONG);
			goto f_err;
			}

		/* now s->rstate == SSL_ST_READ_BODY */
		}

	/* s->rstate == SSL_ST_READ_BODY, get and decode the data */

	if (rr->length > s->packet_length-SPP_RT_HEADER_LENGTH)
		{
		/* now s->packet_length == SPP_RT_HEADER_LENGTH */
		i=rr->length;
		n=ssl3_read_n(s,i,i,1);
		if (n <= 0) return(n); /* error or non-blocking io */
		/* now n == rr->length,
		 * and s->packet_length == SSL3_RT_HEADER_LENGTH + rr->length */
		}

	s->rstate=SSL_ST_READ_HEADER; /* set state for later operations */

	/* At this point, s->packet_length == SSL3_RT_HEADER_LNGTH + rr->length,
	 * and we have that many bytes in s->packet
	 */
	rr->input= &(s->packet[SPP_RT_HEADER_LENGTH]);

	/* ok, we can now read from 's->packet' data into 'rr'
	 * rr->input points at rr->length bytes, which
	 * need to be copied into rr->data by either
	 * the decryption or by the decompression
	 * When the data is 'copied' into the rr->data buffer,
	 * rr->input will be pointed at the new buffer */ 

	/* We now have - encrypted [ MAC [ compressed [ plain ] ] ]
	 * rr->length bytes of encrypted compressed stuff. */

	/* check is not needed I believe */
	if (rr->length > SSL3_RT_MAX_ENCRYPTED_LENGTH+extra)
		{
		al=SSL_AD_RECORD_OVERFLOW;
		SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_ENCRYPTED_LENGTH_TOO_LONG);
		goto f_err;
		}

	/* decrypt in place in 'rr->input' */
	rr->data=rr->input;
        /* Get slice from id. */
        if (rr->slice_id >= s->slices_len) {
            SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_ENCRYPTED_LENGTH_TOO_LONG);
            goto f_err;
        }
        s->cur_slice = &s->slices[rr->slice_id];
        /* We can decrypt this slice. */
        if (s->cur_slice->have_material == 1) {
            enc_err = s->method->ssl3_enc->enc(s,0);
        } else {
            /* Cannot decrypt, just return the still encrypted data. */
            goto done;
        }
	/* enc_err is:
	 *    0: (in non-constant time) if the record is publically invalid.
	 *    1: if the padding is valid
	 *    -1: if the padding is invalid */
	if (enc_err == 0)
		{
		al=SSL_AD_DECRYPTION_FAILED;
		SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_BLOCK_CIPHER_PAD_IS_WRONG);
		goto f_err;
		}

#ifdef TLS_DEBUG
printf("dec %d\n",rr->length);
{ unsigned int z; for (z=0; z<rr->length; z++) printf("%02X%c",rr->data[z],((z+1)%16)?' ':'\n'); }
printf("\n");
#endif

	/* r->length is now the compressed data plus mac */
	if ((sess != NULL) &&
	    (s->enc_read_ctx != NULL) &&
	    (EVP_MD_CTX_md(s->read_hash) != NULL))
		{
		/* s->read_hash != NULL => mac_size != -1 */
		unsigned char *mac = NULL;
		unsigned char mac_tmp[EVP_MAX_MD_SIZE];
		mac_size=EVP_MD_CTX_size(s->read_hash);
		OPENSSL_assert(mac_size <= EVP_MAX_MD_SIZE);

		/* kludge: *_cbc_remove_padding passes padding length in rr->type */
		orig_len = rr->length+((unsigned int)rr->type>>8);

		/* orig_len is the length of the record before any padding was
		 * removed. This is public information, as is the MAC in use,
		 * therefore we can safely process the record in a different
		 * amount of time if it's too short to possibly contain a MAC.
		 */
		if (orig_len < mac_size ||
		    /* CBC records must have a padding length byte too. */
		    (EVP_CIPHER_CTX_mode(s->enc_read_ctx) == EVP_CIPH_CBC_MODE &&
		     orig_len < mac_size+1))
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}

		if (EVP_CIPHER_CTX_mode(s->enc_read_ctx) == EVP_CIPH_CBC_MODE)
			{
			/* We update the length so that the TLS header bytes
			 * can be constructed correctly but we need to extract
			 * the MAC in constant time from within the record,
			 * without leaking the contents of the padding bytes.
			 * */
			mac = mac_tmp;
			ssl3_cbc_copy_mac(mac_tmp, rr, mac_size, orig_len);
			rr->length -= mac_size;
			}
		else
			{
			/* In this case there's no padding, so |orig_len|
			 * equals |rec->length| and we checked that there's
			 * enough bytes for |mac_size| above. */
			rr->length -= mac_size;
			mac = &rr->data[rr->length];
			}

		i=s->method->ssl3_enc->mac(s,md,0 /* not send */);
		if (i < 0 || mac == NULL || CRYPTO_memcmp(md, mac, (size_t)mac_size) != 0)
			enc_err = -1;
		if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH+extra+mac_size)
			enc_err = -1;
		}

	if (enc_err < 0)
		{
		/* A separate 'decryption_failed' alert was introduced with TLS 1.0,
		 * SSL 3.0 only has 'bad_record_mac'.  But unless a decryption
		 * failure is directly visible from the ciphertext anyway,
		 * we should not reveal which kind of error occured -- this
		 * might become visible to an attacker (e.g. via a logfile) */
		al=SSL_AD_BAD_RECORD_MAC;
		SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
		goto f_err;
		}

	/* r->length is now just compressed */
	if (s->expand != NULL)
		{
		if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH+extra)
			{
			al=SSL_AD_RECORD_OVERFLOW;
			SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_COMPRESSED_LENGTH_TOO_LONG);
			goto f_err;
			}
		if (!ssl3_do_uncompress(s))
			{
			al=SSL_AD_DECOMPRESSION_FAILURE;
			SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_BAD_DECOMPRESSION);
			goto f_err;
			}
		}

	if (rr->length > SSL3_RT_MAX_PLAIN_LENGTH+extra)
		{
		al=SSL_AD_RECORD_OVERFLOW;
		SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_DATA_LENGTH_TOO_LONG);
		goto f_err;
		}

	rr->off=0;
	/* So at this point the following is true
	 * ssl->s3->rrec.type 	is the type of record
	 * ssl->s3->rrec.length	== number of bytes in record
	 * ssl->s3->rrec.off	== offset to first valid byte
	 * ssl->s3->rrec.data	== where to take bytes from, increment
	 *			   after use :-).
	 */

	/* we have pulled in a full packet so zero things */
	s->packet_length=0;

	/* just read a 0 length packet */
	if (rr->length == 0)
		{
		empty_record_count++;
		if (empty_record_count > MAX_EMPTY_RECORDS)
			{
			al=SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_RECORD_TOO_SMALL);
			goto f_err;
			}
		goto again;
		}

#if 0
fprintf(stderr, "Ultimate Record type=%d, Length=%d\n", rr->type, rr->length);
#endif

done:
	return(1);

f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
err:
	return(ret);
	}

int spp_read_bytes(SSL *s, int type, unsigned char *buf, int len, int peek)
	{
	int al,i,j,ret;
	unsigned int n;
	SSL3_RECORD *rr;
	void (*cb)(const SSL *ssl,int type2,int val)=NULL;

	if (s->s3->rbuf.buf == NULL) /* Not initialized yet */
		if (!ssl3_setup_read_buffer(s))
			return(-1);

	if ((type && (type != SSL3_RT_APPLICATION_DATA) && (type != SSL3_RT_HANDSHAKE)) ||
	    (peek && (type != SSL3_RT_APPLICATION_DATA)))
		{
		SSLerr(SSL_F_SSL3_READ_BYTES, ERR_R_INTERNAL_ERROR);
		return -1;
		}

	if ((type == SSL3_RT_HANDSHAKE) && (s->s3->handshake_fragment_len > 0))
		/* (partially) satisfy request from storage */
		{
		unsigned char *src = s->s3->handshake_fragment;
		unsigned char *dst = buf;
		unsigned int k;

		/* peek == 0 */
		n = 0;
		while ((len > 0) && (s->s3->handshake_fragment_len > 0))
			{
			*dst++ = *src++;
			len--; s->s3->handshake_fragment_len--;
			n++;
			}
		/* move any remaining fragment bytes: */
		for (k = 0; k < s->s3->handshake_fragment_len; k++)
			s->s3->handshake_fragment[k] = *src++;
		return n;
	}

	/* Now s->s3->handshake_fragment_len == 0 if type == SSL3_RT_HANDSHAKE. */

	if (!s->in_handshake && SSL_in_init(s))
		{
		/* type == SSL3_RT_APPLICATION_DATA */
		i=s->handshake_func(s);
		if (i < 0) return(i);
		if (i == 0)
			{
			SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_SSL_HANDSHAKE_FAILURE);
			return(-1);
			}
		}
start:
	s->rwstate=SSL_NOTHING;

	/* s->s3->rrec.type	    - is the type of record
	 * s->s3->rrec.data,    - data
	 * s->s3->rrec.off,     - offset into 'data' for next read
	 * s->s3->rrec.length,  - number of bytes. */
	rr = &(s->s3->rrec);

	/* get new packet if necessary */
	if ((rr->length == 0) || (s->rstate == SSL_ST_READ_BODY))
		{
                ret=spp_get_record(s);
		if (ret <= 0) return(ret);
		}

	/* we now have a packet which can be read and processed */

	if (s->s3->change_cipher_spec /* set when we receive ChangeCipherSpec,
	                               * reset by ssl3_get_finished */
		&& (rr->type != SSL3_RT_HANDSHAKE))
		{
		al=SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_DATA_BETWEEN_CCS_AND_FINISHED);
		goto f_err;
		}

	/* If the other end has shut down, throw anything we read away
	 * (even in 'peek' mode) */
	if (s->shutdown & SSL_RECEIVED_SHUTDOWN)
		{
		rr->length=0;
		s->rwstate=SSL_NOTHING;
		return(0);
		}


	if (type == rr->type) /* SSL3_RT_APPLICATION_DATA or SSL3_RT_HANDSHAKE */
		{
		/* make sure that we are not getting application data when we
		 * are doing a handshake for the first time */
		if (SSL_in_init(s) && (type == SSL3_RT_APPLICATION_DATA) &&
			(s->enc_read_ctx == NULL))
			{
			al=SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_APP_DATA_IN_HANDSHAKE);
			goto f_err;
			}

		if (len <= 0) return(len);

		if ((unsigned int)len > rr->length)
			n = rr->length;
		else
			n = (unsigned int)len;

		memcpy(buf,&(rr->data[rr->off]),n);
		if (!peek)
			{
			rr->length-=n;
			rr->off+=n;
			if (rr->length == 0)
				{
				s->rstate=SSL_ST_READ_HEADER;
				rr->off=0;
				if (s->mode & SSL_MODE_RELEASE_BUFFERS && s->s3->rbuf.left == 0)
					ssl3_release_read_buffer(s);
				}
			}
		return(n);
		}


	/* If we get here, then type != rr->type; if we have a handshake
	 * message, then it was unexpected (Hello Request or Client Hello). */

	/* In case of record types for which we have 'fragment' storage,
	 * fill that so that we can process the data at a fixed place.
	 */
		{
		unsigned int dest_maxlen = 0;
		unsigned char *dest = NULL;
		unsigned int *dest_len = NULL;

		if (rr->type == SSL3_RT_HANDSHAKE)
			{
			dest_maxlen = sizeof s->s3->handshake_fragment;
			dest = s->s3->handshake_fragment;
			dest_len = &s->s3->handshake_fragment_len;
			}
		else if (rr->type == SSL3_RT_ALERT)
			{
			dest_maxlen = sizeof s->s3->alert_fragment;
			dest = s->s3->alert_fragment;
			dest_len = &s->s3->alert_fragment_len;
			}
#ifndef OPENSSL_NO_HEARTBEATS
		else if (rr->type == TLS1_RT_HEARTBEAT)
			{
			tls1_process_heartbeat(s);

			/* Exit and notify application to read again */
			rr->length = 0;
			s->rwstate=SSL_READING;
			BIO_clear_retry_flags(SSL_get_rbio(s));
			BIO_set_retry_read(SSL_get_rbio(s));
			return(-1);
			}
#endif

		if (dest_maxlen > 0)
			{
			n = dest_maxlen - *dest_len; /* available space in 'dest' */
			if (rr->length < n)
				n = rr->length; /* available bytes */

			/* now move 'n' bytes: */
			while (n-- > 0)
				{
				dest[(*dest_len)++] = rr->data[rr->off++];
				rr->length--;
				}

			if (*dest_len < dest_maxlen)
				goto start; /* fragment was too small */
			}
		}

	/* s->s3->handshake_fragment_len == 4  iff  rr->type == SSL3_RT_HANDSHAKE;
	 * s->s3->alert_fragment_len == 2      iff  rr->type == SSL3_RT_ALERT.
	 * (Possibly rr is 'empty' now, i.e. rr->length may be 0.) */

	/* If we are a client, check for an incoming 'Hello Request': */
	if ((!s->server) &&
		(s->s3->handshake_fragment_len >= 4) &&
		(s->s3->handshake_fragment[0] == SSL3_MT_HELLO_REQUEST) &&
		(s->session != NULL) && (s->session->cipher != NULL))
		{
		s->s3->handshake_fragment_len = 0;

		if ((s->s3->handshake_fragment[1] != 0) ||
			(s->s3->handshake_fragment[2] != 0) ||
			(s->s3->handshake_fragment[3] != 0))
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_BAD_HELLO_REQUEST);
			goto f_err;
			}

		if (s->msg_callback)
			s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE, s->s3->handshake_fragment, 4, s, s->msg_callback_arg);

		if (SSL_is_init_finished(s) &&
			!(s->s3->flags & SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS) &&
			!s->s3->renegotiate)
			{
			ssl3_renegotiate(s);
			if (ssl3_renegotiate_check(s))
				{
				i=s->handshake_func(s);
				if (i < 0) return(i);
				if (i == 0)
					{
					SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_SSL_HANDSHAKE_FAILURE);
					return(-1);
					}

				if (!(s->mode & SSL_MODE_AUTO_RETRY))
					{
					if (s->s3->rbuf.left == 0) /* no read-ahead left? */
						{
						BIO *bio;
						/* In the case where we try to read application data,
						 * but we trigger an SSL handshake, we return -1 with
						 * the retry option set.  Otherwise renegotiation may
						 * cause nasty problems in the blocking world */
						s->rwstate=SSL_READING;
						bio=SSL_get_rbio(s);
						BIO_clear_retry_flags(bio);
						BIO_set_retry_read(bio);
						return(-1);
						}
					}
				}
			}
		/* we either finished a handshake or ignored the request,
		 * now try again to obtain the (application) data we were asked for */
		goto start;
		}
	/* If we are a server and get a client hello when renegotiation isn't
	 * allowed send back a no renegotiation alert and carry on.
	 * WARNING: experimental code, needs reviewing (steve)
	 */
	if (s->server &&
		SSL_is_init_finished(s) &&
    		!s->s3->send_connection_binding &&
		(s->version > SSL3_VERSION) &&
		(s->s3->handshake_fragment_len >= 4) &&
		(s->s3->handshake_fragment[0] == SSL3_MT_CLIENT_HELLO) &&
		(s->session != NULL) && (s->session->cipher != NULL) &&
		!(s->ctx->options & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION))
		
		{
		/*s->s3->handshake_fragment_len = 0;*/
		rr->length = 0;
		ssl3_send_alert(s,SSL3_AL_WARNING, SSL_AD_NO_RENEGOTIATION);
		goto start;
		}
	if (s->s3->alert_fragment_len >= 2)
		{
		int alert_level = s->s3->alert_fragment[0];
		int alert_descr = s->s3->alert_fragment[1];

		s->s3->alert_fragment_len = 0;

		if (s->msg_callback)
			s->msg_callback(0, s->version, SSL3_RT_ALERT, s->s3->alert_fragment, 2, s, s->msg_callback_arg);

		if (s->info_callback != NULL)
			cb=s->info_callback;
		else if (s->ctx->info_callback != NULL)
			cb=s->ctx->info_callback;

		if (cb != NULL)
			{
			j = (alert_level << 8) | alert_descr;
			cb(s, SSL_CB_READ_ALERT, j);
			}

		if (alert_level == 1) /* warning */
			{
			s->s3->warn_alert = alert_descr;
			if (alert_descr == SSL_AD_CLOSE_NOTIFY)
				{
				s->shutdown |= SSL_RECEIVED_SHUTDOWN;
				return(0);
				}
			/* This is a warning but we receive it if we requested
			 * renegotiation and the peer denied it. Terminate with
			 * a fatal alert because if application tried to
			 * renegotiatie it presumably had a good reason and
			 * expects it to succeed.
			 *
			 * In future we might have a renegotiation where we
			 * don't care if the peer refused it where we carry on.
			 */
			else if (alert_descr == SSL_AD_NO_RENEGOTIATION)
				{
				al = SSL_AD_HANDSHAKE_FAILURE;
				SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_NO_RENEGOTIATION);
				goto f_err;
				}
#ifdef SSL_AD_MISSING_SRP_USERNAME
			else if (alert_descr == SSL_AD_MISSING_SRP_USERNAME)
				return(0);
#endif
			}
		else if (alert_level == 2) /* fatal */
			{
			char tmp[16];

			s->rwstate=SSL_NOTHING;
			s->s3->fatal_alert = alert_descr;
			SSLerr(SSL_F_SSL3_READ_BYTES, SSL_AD_REASON_OFFSET + alert_descr);
			BIO_snprintf(tmp,sizeof tmp,"%d",alert_descr);
			ERR_add_error_data(2,"SSL alert number ",tmp);
			s->shutdown|=SSL_RECEIVED_SHUTDOWN;
			SSL_CTX_remove_session(s->ctx,s->session);
			return(0);
			}
		else
			{
			al=SSL_AD_ILLEGAL_PARAMETER;
			SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_UNKNOWN_ALERT_TYPE);
			goto f_err;
			}

		goto start;
		}

	if (s->shutdown & SSL_SENT_SHUTDOWN) /* but we have not received a shutdown */
		{
		s->rwstate=SSL_NOTHING;
		rr->length=0;
		return(0);
		}

	if (rr->type == SSL3_RT_CHANGE_CIPHER_SPEC)
		{
		/* 'Change Cipher Spec' is just a single byte, so we know
		 * exactly what the record payload has to look like */
		if (	(rr->length != 1) || (rr->off != 0) ||
			(rr->data[0] != SSL3_MT_CCS))
			{
			al=SSL_AD_ILLEGAL_PARAMETER;
			SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_BAD_CHANGE_CIPHER_SPEC);
			goto f_err;
			}

		/* Check we have a cipher to change to */
		if (s->s3->tmp.new_cipher == NULL)
			{
			al=SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_CCS_RECEIVED_EARLY);
			goto f_err;
			}

		if (!(s->s3->flags & SSL3_FLAGS_CCS_OK))
			{
			al=SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_CCS_RECEIVED_EARLY);
			goto f_err;
			}

		s->s3->flags &= ~SSL3_FLAGS_CCS_OK;

		rr->length=0;

		if (s->msg_callback)
			s->msg_callback(0, s->version, SSL3_RT_CHANGE_CIPHER_SPEC, rr->data, 1, s, s->msg_callback_arg);

		s->s3->change_cipher_spec=1;
		if (!ssl3_do_change_cipher_spec(s))
			goto err;
		else
			goto start;
		}

	/* Unexpected handshake message (Client Hello, or protocol violation) */
	if ((s->s3->handshake_fragment_len >= 4) &&	!s->in_handshake)
		{
		if (((s->state&SSL_ST_MASK) == SSL_ST_OK) &&
			!(s->s3->flags & SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS))
			{
#if 0 /* worked only because C operator preferences are not as expected (and
       * because this is not really needed for clients except for detecting
       * protocol violations): */
			s->state=SSL_ST_BEFORE|(s->server)
				?SSL_ST_ACCEPT
				:SSL_ST_CONNECT;
#else
			s->state = s->server ? SSL_ST_ACCEPT : SSL_ST_CONNECT;
#endif
			s->renegotiate=1;
			s->new_session=1;
			}
		i=s->handshake_func(s);
		if (i < 0) return(i);
		if (i == 0)
			{
			SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_SSL_HANDSHAKE_FAILURE);
			return(-1);
			}

		if (!(s->mode & SSL_MODE_AUTO_RETRY))
			{
			if (s->s3->rbuf.left == 0) /* no read-ahead left? */
				{
				BIO *bio;
				/* In the case where we try to read application data,
				 * but we trigger an SSL handshake, we return -1 with
				 * the retry option set.  Otherwise renegotiation may
				 * cause nasty problems in the blocking world */
				s->rwstate=SSL_READING;
				bio=SSL_get_rbio(s);
				BIO_clear_retry_flags(bio);
				BIO_set_retry_read(bio);
				return(-1);
				}
			}
		goto start;
		}

	switch (rr->type)
		{
	default:
#ifndef OPENSSL_NO_TLS
		/* TLS up to v1.1 just ignores unknown message types:
		 * TLS v1.2 give an unexpected message alert.
		 */
		if (s->version >= TLS1_VERSION && s->version <= TLS1_1_VERSION)
			{
			rr->length = 0;
			goto start;
			}
#endif
		al=SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_UNEXPECTED_RECORD);
		goto f_err;
	case SSL3_RT_CHANGE_CIPHER_SPEC:
	case SSL3_RT_ALERT:
	case SSL3_RT_HANDSHAKE:
		/* we already handled all of these, with the possible exception
		 * of SSL3_RT_HANDSHAKE when s->in_handshake is set, but that
		 * should not happen when type != rr->type */
		al=SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_READ_BYTES,ERR_R_INTERNAL_ERROR);
		goto f_err;
	case SSL3_RT_APPLICATION_DATA:
		/* At this point, we were expecting handshake data,
		 * but have application data.  If the library was
		 * running inside ssl3_read() (i.e. in_read_app_data
		 * is set) and it makes sense to read application data
		 * at this point (session renegotiation not yet started),
		 * we will indulge it.
		 */
		if (s->s3->in_read_app_data &&
			(s->s3->total_renegotiations != 0) &&
			((
				(s->state & SSL_ST_CONNECT) &&
				(s->state >= SSL3_ST_CW_CLNT_HELLO_A) &&
				(s->state <= SSL3_ST_CR_SRVR_HELLO_A)
				) || (
					(s->state & SSL_ST_ACCEPT) &&
					(s->state <= SSL3_ST_SW_HELLO_REQ_A) &&
					(s->state >= SSL3_ST_SR_CLNT_HELLO_A)
					)
				))
			{
			s->s3->in_read_app_data=2;
			return(-1);
			}
		else
			{
			al=SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_SSL3_READ_BYTES,SSL_R_UNEXPECTED_RECORD);
			goto f_err;
			}
		}
	/* not reached */

f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
err:
	return(-1);
	}
