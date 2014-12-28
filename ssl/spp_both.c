#include <limits.h>
#include <string.h>
#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

int spp_generate_slice_keys(SSL *s, int client) {
    int i;    
    for (i = 0; i < s->slices_len; i++) {
        if (client) {
            if (RAND_pseudo_bytes(&(s->slices[i].client_read_mat[0]), EVP_MAX_KEY_LENGTH) <= 0)
                return -1;
            if (RAND_pseudo_bytes(&(s->slices[i].client_write_mat[0]), EVP_MAX_KEY_LENGTH) <= 0)
                return -1;
        } else {
            if (RAND_pseudo_bytes(&(s->slices[i].server_read_mat[0]), EVP_MAX_KEY_LENGTH) <= 0)
                return -1;
            if (RAND_pseudo_bytes(&(s->slices[i].server_write_mat[0]), EVP_MAX_KEY_LENGTH) <= 0)
                return -1;
        }
    }
    return 1;
}

SPP_PROXY* spp_get_next_proxy(SSL *s, int forward) {
    int i;
    if (forward) {
        for (i = 0; i < s->proxies_len; i++) {
            if (s->proxies[i].done == 0) {
                return &(s->proxies[i]);
            }
        }
    } else {
        for (i = s->proxies_len - 1; i >= 0; i--) {
            if (s->proxies[i].done == 0) {
                return &(s->proxies[i]);
            }
        }
    }
    return NULL;
}