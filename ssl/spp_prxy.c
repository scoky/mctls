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
			spp_accept,
			spp_connect,
			spp_get_proxy_method)

/* TODO: Maybe needs it's own accept and connect methods?
 * spp_proxy_accept()
 * app_proxy_connect() */    
