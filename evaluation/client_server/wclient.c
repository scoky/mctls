/* A simple HTTPS client

   It connects to the server, makes an HTTP
   request and waits for the response
*/
#include "common.h"
#define KEYFILE "client.pem"
#define PASSWORD "password"



int tcp_connect(host,port)
  char *host;
  int port;
  {
    struct hostent *hp;
    struct sockaddr_in addr;
    int sock;
    
	if(!(hp=gethostbyname(host))){
		berr_exit("Couldn't resolve host");
	}
    memset(&addr,0,sizeof(addr));
    addr.sin_addr=*(struct in_addr*)
      hp->h_addr_list[0];
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);

    if((sock=socket(AF_INET,SOCK_STREAM,
      IPPROTO_TCP))<0)
      err_exit("Couldn't create socket");
    if(connect(sock,(struct sockaddr *)&addr,
      sizeof(addr))<0)
      err_exit("Couldn't connect socket");
    
    return sock;
  }

/* Check that the common name matches the
   host name*/
void check_cert(ssl,host)
  SSL *ssl;
  char *host;
  {
    X509 *peer;
    char peer_CN[256];
  	
	long res = SSL_get_verify_result(ssl);  
	if ((res == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) || (res == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)){
		printf("[Matteo] Self signed certificate accepted\n"); 
	} else {
    	if(res != X509_V_OK)
			berr_exit("Certificate doesn't verify\n");
	}

    /*Check the cert chain. The chain length
      is automatically checked by OpenSSL when
      we set the verify depth in the ctx */

    /*Check the common name*/
    peer=SSL_get_peer_certificate(ssl);
    X509_NAME_get_text_by_NID
      (X509_get_subject_name(peer),
      NID_commonName, peer_CN, 256);


      // WARNING NO VALIDATION Validate the hostname
  if (1) {
    
      printf("Peer_CN = %s\n", peer_CN);
      printf("Host = %s\n\n", host);
      //err_exit("Common name doesn't match host name");
    }
  }


   

static char *REQUEST_TEMPLATE=
   "GET / HTTP/1.0\r\nUser-Agent:"
   "EKRClient\r\nHost: %s:%d\r\n\r\n";

static char *host=HOST;
static int port=PORT;
static int require_server_auth=1;

static int http_request(ssl)
  SSL *ssl;
  {
    char *request=0;
    char buf[BUFSIZZ];
    int r;
    int len, request_len;
    
    /* Now construct our HTTP request */
    request_len=strlen(REQUEST_TEMPLATE)+
      strlen(host)+6;
    if(!(request=(char *)malloc(request_len)))
      err_exit("Couldn't allocate request");
    snprintf(request,request_len,REQUEST_TEMPLATE,
      host,port);

    /* Find the exact request_len */
    request_len=strlen(request);

    r=SSL_write(ssl,request,request_len);
    switch(SSL_get_error(ssl,r)){      
      case SSL_ERROR_NONE:
        if(request_len!=r)
          err_exit("Incomplete write!");
        break;
        default:
          berr_exit("SSL write problem");
    }
    
    /* Now read the server's response, assuming
       that it's terminated by a close */
    while(1){
      r=SSL_read(ssl,buf,BUFSIZZ);
      switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
          len=r;
          break;
        case SSL_ERROR_ZERO_RETURN:
          goto shutdown;
        case SSL_ERROR_SYSCALL:
          fprintf(stderr,
            "SSL Error: Premature close\n");
          goto done;
        default:
          berr_exit("SSL read problem");
      }

      fwrite(buf,1,len,stdout);
    }
    
  shutdown:
    r=SSL_shutdown(ssl);
    switch(r){
      case 1:
        break; /* Success */
      case 0:
      case -1:
      default:
        berr_exit("Shutdown failed");
    }
    
  done:
    SSL_free(ssl);
    free(request);
    return(0);
  }
    
int main(argc,argv)
  int argc;
  char **argv;
  {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio;
    int sock;
    extern char *optarg;
    int c;

    while((c=getopt(argc,argv,"h:p:i"))!=-1){
      switch(c){
        case 'h':
          if(!(host=strdup(optarg)))
            err_exit("Out of memory");
          break;
        case 'p':
          if(!(port=atoi(optarg)))
            err_exit("Bogus port specified");
          break;
        case 'i':
          require_server_auth=0;
          break;
      }
    }
    printf("Host: %s, port %d\n", host, port);
    /* Build our SSL context*/
    ctx=initialize_ctx(KEYFILE,PASSWORD);

    /* Connect the TCP socket*/
    sock=tcp_connect(host,port);

    /* Connect the SSL socket */
    ssl=SSL_new(ctx);
    sbio=BIO_new_socket(sock,BIO_NOCLOSE);
    SSL_set_bio(ssl,sbio,sbio);

    if(SSL_connect(ssl)<=0)
      berr_exit("SSL connect error");
    if(require_server_auth)
      check_cert(ssl,host);
 
    /* Now make our HTTP request */
    http_request(ssl);

    /* Shutdown the socket */
    destroy_ctx(ctx);
    close(sock);

    exit(0);
  }

