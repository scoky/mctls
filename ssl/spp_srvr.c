#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

static const SSL_METHOD *spp_get_server_method(int ver);
static const SSL_METHOD *spp_get_server_method(int ver)
	{
	if (ver == SPP_VERSION)
		return SPP_server_method();
	return NULL;
	}

IMPLEMENT_spp_meth_func(SPP_VERSION, SPP_server_method,
			spp_accept,
			ssl_undefined_function,
			spp_get_server_method)
        
int spp_accept(SSL *s) {
    /* TODO: replace with new accept method */
    /* Set the slices information. */
    return 0;
}
