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
    /* TODO: Method for client to connect */
    return 0;
}