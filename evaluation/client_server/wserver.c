// A simple https server orginally provided by Ilias

#include "common.h"
#define KEYFILE "server.pem"
#define PASSWORD "password"
#define DHFILE "dh1024.pem"
#include <openssl/e_os2.h>

#define DEBUG


int tcp_listen()
  {
    int sock;
    struct sockaddr_in sin;
    int val=1;


    if((sock=socket(AF_INET,SOCK_STREAM,0))<0)
      err_exit("Couldn't make socket");
    
    memset(&sin,0,sizeof(sin));
    sin.sin_addr.s_addr=INADDR_ANY;
    sin.sin_family=AF_INET;
    sin.sin_port=htons(PORT);
    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,
      &val,sizeof(val));
    
    if(bind(sock,(struct sockaddr *)&sin,
      sizeof(sin))<0)
      berr_exit("Couldn't bind");
    listen(sock,5);  

    return(sock);
  }

void load_dh_params(ctx,file)
  SSL_CTX *ctx;
  char *file;
  {
    DH *ret=0;
    BIO *bio;

    if ((bio=BIO_new_file(file,"r")) == NULL)
      berr_exit("Couldn't open DH file");

    ret=PEM_read_bio_DHparams(bio,NULL,NULL,
      NULL);
    BIO_free(bio);
    if(SSL_CTX_set_tmp_dh(ctx,ret)<0)
      berr_exit("Couldn't set DH parameters");
  }

void generate_eph_rsa_key(ctx)
  SSL_CTX *ctx;
  {
    RSA *rsa;

    rsa=RSA_generate_key(512,RSA_F4,NULL,NULL);
    
    if (!SSL_CTX_set_tmp_rsa(ctx,rsa))
      berr_exit("Couldn't set RSA key");

    RSA_free(rsa);
  }
    
// Compute the size of a file to be served
int calculate_file_size(char *filename){ 

	FILE *fp; 	
	int sz = 0; 

	// Open file 
 	fp = fopen(filename,"r");
 
	// Check for errors while opening file
	if(fp == NULL){
		printf("Error while opening file %s.\r\n", filename);
		exit(-1);
	}
	
	// Seek  to the end of the file and ask for position 
	fseek(fp, 0L, SEEK_END);
	sz = ftell(fp);
	//fseek(fp, 0L, SEEK_SET);

	// Close file 
	fclose (fp);
	
	// Return file size 
	#ifdef DEBUG
	printf ("File requested is <<%s>> with size <<%d bytes>>\n", filename, sz); 
	#endif 
	return sz; 
}

// Function to print a prox list
void print_proxy_list(SPP_PROXY **proxies, int N){
	int i; 

	#ifdef DEBUG
	printf("Print proxy list. There are %d available proxies.\r\n", N);
	#endif

	// Iterate through list 
	for (i = 0; i < N; i++){
		printf("Proxy %d -- %s\r\n", i, proxies[i]->address);
	}
}
 
// Temporary http serve with SPP
static int http_serve_SPP(SSL *ssl, int s){

	int N_proxies; 
	N_proxies = ssl->proxies_len; 

	int i; 
	for (i = 0; i < N_proxies; i++){
		printf("Proxy: %s\n", ssl->proxies[i]->address); 
	}

	/*
	int N_proxies; 
	SPP_PROXY *proxies = NULL; 

	// Get proxy list 
	#ifdef DEBUG
	printf("Http serve SPP - Getting proxy list\n"); 
	#endif
	if ( !SPP_get_proxies(ssl, &proxies, &N_proxies)){
		return -1; 
	}
	
	#ifdef DEBUG
	printf("Http serve SPP - %d proxies are in the path. Printing proxy list\n", N_proxies); 
	#endif
	print_proxy_list(proxies, N_proxies); 
	
	#ifdef DEBUG
	printf("Http serve SPP - All good :-)\n"); 
	#endif
	*/
	// all correct 			
	return 0; 
}

// Regular http serve
static int http_serve(SSL *ssl, int s){
  
	char buf[BUFSIZZ];
	int r; //len; //len seems useless...
	BIO *io,*ssl_bio;
    
	io = BIO_new(BIO_f_buffer());	
	ssl_bio = BIO_new(BIO_f_ssl());
	BIO_set_ssl(ssl_bio, ssl, BIO_CLOSE);
	BIO_push(io, ssl_bio);
    	
	while(1){
		r = BIO_gets(io, buf, BUFSIZZ-1);
	
		
		if (SSL_get_error(ssl, r) == SSL_ERROR_NONE){
		} else {
			berr_exit("SSL read problem");
		}
		
		//Look for the blank line that signals the end of the HTTP headers //
		if(!strcmp(buf, "\r\n") || !strcmp(buf, "\n")){
			break; 
		}
	}
    
	// Put 200 OK on the wire 
	if((r = BIO_puts (io, "HTTP/1.0 200 OK\r\n")) <= 0){
		err_exit("Write error");
	}

	// Put server name on the wire 
    if((r = BIO_puts (io,"Server: Svarvel\r\n\r\n")) <= 0){
		err_exit("Write error");
	}
	
	if((r=BIO_puts (io,"Server test page\r\n"))<=0){
		err_exit("Write error");
	}
  	
	// Send file index.html -- TO DO, extend to a requested name
	BIO *file;
	static int bufsize = BUFSIZZ;
	int total_bytes = 0, j = 0, file_size = 0; 

	// Determine file size -- TO DO: integration with BIO stuff 
	file_size = calculate_file_size("index.html"); 
	
	// Open requested file 
	if ((file = BIO_new_file("index.html","r")) == NULL){                
		BIO_puts(io, "Error opening file"); // what is text? ERROR
        BIO_printf(io,"Error opening index.html\r\n");
		goto write_error;
	}

	// Put file on the wire 
	for (;;){
		// Read bufsize from requested file 
		int i = BIO_read(file, buf, bufsize);
		if (i <= 0){
			break; 
		}

		// Keep count of bytes sent on the wire 
		total_bytes += i;
		
		// Check if too many losses 
		if (total_bytes > (3 * file_size)){
			total_bytes = 0;
			fprintf(stderr,"RENEGOTIATE\n");
			SSL_renegotiate(ssl); 
		}
		
		// ??
		for (j = 0; j < i; ){
			// After 13 attempts, re-negotate at SSL level 
			static int count = 0; 
			if (++count == 13) { 
				SSL_renegotiate(ssl); 
			} 

			int k = BIO_write(io, &(buf[j]), i-j);
			if (k <= 0){
				if (! BIO_should_retry(io)){
					goto write_error; 
				}else {
					BIO_printf(io, "rewrite W BLOCK\n");
					}
				}else{
					j += k;
				}
			write_error:
				BIO_free(file);
				break; 
			}

		if((r = BIO_flush(io))<0){
			err_exit("Error flushing BIO");
		}
		
		r = SSL_shutdown(ssl);
		if( !r ){
      /* If we called SSL_shutdown() first then
         we always get return value of '0'. In
         this case, try again, but first send a
         TCP FIN to trigger the other side's
         close_notify*/
			shutdown(s,1);
			r = SSL_shutdown(ssl);
    	}
		switch(r){  
			case 1:
        		break; /* Success */
			case 0:
			case -1:
			default:
			berr_exit("Shutdown failed");
		}
    } // end for loop 

    SSL_free(ssl);
    close(s);

    return(0);
  }

// Usage function 
void usage(void){
	printf("usage: wserver -f \n");
	printf("-f:   protocol requested: ssl, spp.\n");
	exit(-1);
}


// Main function  
int main(int argc, char **argv){
	int sock, s;
	BIO *sbio;
	SSL_CTX *ctx;
	SSL *ssl;
	int r;
	pid_t pid;
	char *proto; 						// protocol type 
	extern char *optarg;                // user input parameters
	int c; 								// user iput from getopt

	// Handle user input parameters
	while((c = getopt(argc, argv, "f:")) != -1){
			switch(c){
				// Protocol 
				case 'f':
					if(! (proto = strdup(optarg) ))
						err_exit("Out of memory");
					break; 
			}
	}

	// Check that input parameters are correct 
	#ifdef DEBUG
	printf("Parameters count: %d\n", argc);
	#endif 
	if (argc == 1){
		usage();
	}

	// Build our SSL context
	ctx = initialize_ctx(KEYFILE, PASSWORD);
	load_dh_params(ctx,DHFILE);
   
	// Socket in listen state
	sock = tcp_listen();

	while(1){
		if((s = accept(sock, 0, 0)) < 0){
			err_exit("Problem socket accept\n");
		}

		if((pid = fork())){
			close(s);
		} else {
			sbio = BIO_new_socket(s, BIO_NOCLOSE);
			ssl = SSL_new(ctx);
			SSL_set_bio(ssl, sbio, sbio);

			// SSL Accept 
			if((r = SSL_accept(ssl) <= 0)){
				berr_exit("SSL accept error");
			} else {
				#ifdef DEBUG
				if (strcmp(proto, "ssl") == 0){ 		
					printf("SSL accept OK\n"); 
				}else{
					printf("SPP accept OK\n"); 
				}
				#endif
			}
    
			// Serve some content here 
			if (strcmp(proto, "spp") == 0){ 
				http_serve_SPP(ssl, s);
			} else {
				http_serve(ssl, s);
			}

			// ? Exit ? 
			exit(0);
		}
	}
	
	// Clean context
	destroy_ctx(ctx);
	
	// ? Exit ? 
	exit(0);
  }
