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
        
/* Gonna need some callbacks here. For example, to get a connection 
 * to the next proxy / server. */

int spp_proxy_accept(SSL *s) {
    /* TODO: replace with new accept method */
    /* Set the slices information. */
    return 0;
}   
