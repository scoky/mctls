#include <stdio.h>
#include <openssl/objects.h>
#include "ssl_locl.h"

static const SSL_METHOD *spp_get_method(int ver)
	{
	if (ver == SPP_VERSION)
		return SPP_method();
	return NULL;
	}

IMPLEMENT_spp_meth_func(SPP_VERSION, SPP_method,
			ssl3_accept,
			ssl3_connect,
			spp_get_method)
