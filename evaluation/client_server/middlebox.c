// A simple https server orginally provided by Ilias

#include "common.h"
#define KEYFILE "server.pem"
#define PASSWORD "password"
#define DHFILE "dh1024.pem"
#include <openssl/e_os2.h>

#define DEBUG
#define MIDDLEBOX_PORT 8423

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
    sin.sin_port=htons(MIDDLEBOX_PORT);
    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,
      &val,sizeof(val));
    
    if(bind(sock,(struct sockaddr *)&sin,
      sizeof(sin))<0)
      berr_exit("Couldn't bind");
    listen(sock,5);  

    #ifdef DEBUG
	printf("Listening at port: %d\n", MIDDLEBOX_PORT); 
	#endif

    return(sock);
  }




// TCP connect function 
int tcp_connect(char *host, int port){

	struct hostent *hp;
	struct sockaddr_in addr;
	int sock;

	// Resolve host 
	if(!(hp = gethostbyname(host))){
		berr_exit("Couldn't resolve host");
	}
	#ifdef DEBUG
	printf("Host resolved\n"); 
	#endif

	memset(&addr, 0, sizeof(addr));
	addr.sin_addr = *(struct in_addr*)
	hp->h_addr_list[0];
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if((sock=socket(AF_INET,SOCK_STREAM, IPPROTO_TCP))<0){
		err_exit("Couldn't create socket");
	}
	#ifdef DEBUG
	printf("Socket created\n"); 
	#endif

	if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0){
		err_exit("Couldn't connect socket");
	}
	#ifdef DEBUG
	printf("Socket connected\n"); 
	#endif
	
	return sock;
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
    
// Check for SSL_write error (just write at this point) -- TO DO: check behavior per slice 
void check_SSL_write_error(SSL *ssl, int r, int request_len){
	
	switch(SSL_get_error(ssl, r)){
		case SSL_ERROR_NONE:
			if(request_len != r){
				err_exit("Incomplete write!");
			}
			break;

		default:
			berr_exit("SSL write problem");
	}
}




// Simple test for SPP
static int print_ssl_debug_info(SSL *ssl){

	int N_proxies, N_slices, i; 
	
	// print proxies
	N_proxies = ssl->proxies_len; 
	for (i = 0; i < N_proxies; i++){
		printf("Proxy: %s\n", ssl->proxies[i]->address); 
	}

	// print slices
	N_slices = ssl->slices_len; 
	for (i = 0; i < N_slices; i++){
		printf("Slice with ID %d and purpose %s\n", ssl->slices[i]->slice_id, ssl->slices[i]->purpose); 
	}

	// All good	
	return 0; 
}



// Usage function 
void usage(void){
	printf("usage: wserver -f \n");
	printf("-f:   protocol requested: ssl, spp.\n");
	exit(-1);
}




SSL* SPP_Callback(SSL *ssl, char *address){
	#ifdef DEBUG
    printf("Callback called with address: %s\n", address);
    #endif

	SSL_CTX *ctx;							// SSL context
	SSL *new_ssl;								// SSL context
	BIO *sbio;								// ?
	int sock;								// socket
	char* ipv4 = strtok(address, ":");	// ip
    int port = atoi(strtok(NULL, ":"));	// port 


    #ifdef DEBUG
    printf("Connecting to next hop: %s %d\n", ipv4, port);
    #endif

	ctx = initialize_ctx(KEYFILE, PASSWORD, "spp");
	new_ssl = SSL_new(ctx);
	sock = tcp_connect(ipv4, port);
	sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(new_ssl, sbio, sbio);

    #ifdef DEBUG
    printf("Connected to next hop...: %s %d\n", ipv4, port);
    #endif

    return new_ssl;
}





/*
For testing purposes only,
this will overwrite the ssl connection struct with valid values, 
till the protocol is ready... 

DELETE WHEN SPP IS READY
*/ 
SSL* fake_SPP_connection(SSL *ssl)
{
	printf("[middlebox] ******\nWARNING: FAKING callback!\n********\n\n");

	//setup end server info...
	char next_hop_address[] = "127.0.0.1:4433"; //the address of the next hp. this should be given by the call-back...
   
	//fake callback...
	SSL* next_ssl = SPP_Callback(ssl, next_hop_address);

	#ifdef DEBUG
	printf("[middlebox] DONE Callback...\n FAKING CONNECTION\n");
	#endif 
	/* we might need to fake the connect call too */


	// Create slices_n slices with incremental purpose 

	// SPP CONNECT 
	//only for fakeing...



	SPP_PROXY *proxies[0];
	SPP_SLICE *slice_set[1];
	char *newPurpose;  
	char str[30]; 
	sprintf (str, "slices_%d", 0); 
	newPurpose = (char *)malloc(strlen(str));    
	strcpy(newPurpose, str);

	slice_set[0] = SPP_generate_slice(next_ssl, newPurpose); 

	#ifdef DEBUG
	printf("[DEBUG] Generated slices %d with purpose %s\n", slice_set[0]->slice_id, slice_set[0]->purpose); 
	#endif

	SPP_assign_proxy_read_slices(next_ssl, proxies[0], slice_set, 1);
	#ifdef DEBUG
	printf("[middlebox] SPP_connect to next hop... (this should be removed when library is ready)\n");
	#endif 
	
	if (SPP_connect(next_ssl, slice_set, 1, proxies, 0) <= 0){
			berr_exit("[middlebox] SPP connect error");
	}
	
	#ifdef DEBUG
	printf("[middlebox] SPP_connect SUCCEDED\n");
	#endif 
	
	return next_ssl;
}


int handle_previous_hop_data(SSL* prev_ssl, SSL* next_ssl)
{  
	
    int r,w; 
	char buf[BUFSIZZ];

	// Read HTTP GET (assuming a single read is enough)
	while(1){


		#ifdef DEBUG
		printf("[middlebox-p] Waiting to read data from previous hop\n");
		#endif
		SPP_SLICE *slice;       
		SPP_CTX *ctx;           
		r = SPP_read_record(prev_ssl, buf, BUFSIZZ, &slice, &ctx);
		#ifdef DEBUG
		printf("[middlebox-p] Got data from previous hop!\n");
		#endif


		if (SSL_get_error(prev_ssl, r) == SSL_ERROR_NONE){
		} else {
			berr_exit("[middlebox-p] SSL read problem (from previous hop)");
		}
		
		#ifdef DEBUG
		printf("[middlebox-p] Request received (from previous hop) (length %d bytes):\n", r); 
		printf("****\n%s\n***\n", buf); 

		printf("[middlebox-p] Forwarding record to  next hop\n"); 
		#endif


		w = SPP_write_record(next_ssl, buf, r, next_ssl->slices[0]);

		//Look for the blank line that signals the end of the HTTP header
		if(r == 0 ){
			break; 
		}
	}

	#ifdef DEBUG
	printf("[middlebox-p] Shutting down previous hop handler thread!\n");
	#endif
	// Shutdown SSL - TO DO (check what happens here) 
	r = SSL_shutdown(prev_ssl);

	// Verify that all went good 
	switch(r){  
		case 1:
       		break; // Success
		case 0:
		case -1:
		default: // Error 
			berr_exit("[middlebox-p] Shutdown failed");
	}

	// free SSL 
    SSL_free(prev_ssl);
	// All good 
    return(0);
}


int handle_next_hop_data(SSL* prev_ssl, SSL* next_ssl)
{  
    int r,w ; 
	char buf[BUFSIZZ];

	// Read HTTP GET (assuming a single read is enough)
	while(1){


		#ifdef DEBUG
		printf("[middlebox-n] Waiting to read data from next hop\n");
		#endif
		SPP_SLICE *slice;       
		SPP_CTX *ctx;           
		r = SPP_read_record(next_ssl, buf, BUFSIZZ, &slice, &ctx);
		#ifdef DEBUG
		printf("[middlebox-n] Got data from next hop!\n");
		#endif


		if (SSL_get_error(next_ssl, r) == SSL_ERROR_NONE){
		} else {
			berr_exit("[middlebox-n] SSL read problem (from next hop)");
		}
		
		#ifdef DEBUG
		printf("[middlebox-n] Data received (from next hop):\n"); 
		printf("****\n%s\n***\n", buf); 

		printf("[middlebox-n] Forwarding record to  previous hop\n"); 
		#endif

		w = SPP_write_record(prev_ssl, buf, r, prev_ssl->slices[0]);
		check_SSL_write_error(prev_ssl, w, r); 
		
		// End of socket....
		if(r == 0 ){
			break; 
		}
	}

	#ifdef DEBUG
	printf("[middlebox-n] Shutting down next hop handler thread!\n");
	#endif
	// Shutdown SSL - TO DO (check what happens here) 
	r = SSL_shutdown(next_ssl);

	// Verify that all went good 
	switch(r){  
		case 1:
       		break; // Success
		case 0:
		case -1:
		default: // Error 
			berr_exit("[middlebox-n] Shutdown failed");
	}

	// free SSL 
    SSL_free(next_ssl);


	// All good 
    return(0);
}





int handle_data(SSL* prev_ssl, SSL* next_ssl)
{
	pid_t next_handler;

	#ifdef DEBUG
	printf("[middlebox] Initializing data handlers\n");
		#endif

	if( (next_handler = fork())) 
	{
		// handle traffic from client
		handle_previous_hop_data(prev_ssl, next_ssl);
		//TODO: wait for child before returning

	}
	else 
	{
		//child 
		handle_next_hop_data(prev_ssl, next_ssl);
	}


	#ifdef DEBUG
	printf("[middlebox] Exiting data handler!\n");
	#endif
	return 0;
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

	proto = "spp";
	
	ctx = initialize_ctx(KEYFILE, PASSWORD, "middlebox");
	load_dh_params(ctx,DHFILE);
   
	// Socket in listen state
	sock = tcp_listen();

	while(1){
		if((s = accept(sock, 0, 0)) < 0){
			err_exit("Problem socket accept\n");
		}
		// fork a new proces 
		if((pid = fork())){
			close(s);
		} else {
			sbio = BIO_new_socket(s, BIO_NOCLOSE);
			ssl = SSL_new(ctx);
			SSL_set_bio(ssl, sbio, sbio);

			// SSL Accept 
/*			// Proxies use SPP_proxy instead of SSL_accept to perform the handshake
			if((r = SSL_accept(ssl) <= 0)){
				berr_exit("SPP accept error");
			} else {
				#ifdef DEBUG		
					printf("SPP accept OK\n"); 
				#endif
			}

*/

			SSL** ssl_next = NULL;
			SSL* (*connect_func)(SSL *, char *)  = SPP_Callback;
			const char *prxy_address = "localhost:8423";
			if ((r = SPP_proxy(ssl, prxy_address, connect_func, ssl_next)) <= 0) {
				berr_exit("SPP proxy error");
			} else {
				#ifdef DEBUG            
                                        printf("SPP proxy OK\n"); 
                                #endif
			}

			#ifdef DEBUG
			printf("[middlebox] GOT SSL CONNECTION. PRINTING SPP DEBUG INFO: \n");
			print_ssl_debug_info(ssl);
			printf("[middlebox] Calling SPP_PROXY\n");
			#endif

			//WARNING, THIS SHOULD BE ENABLED !!!
			//SPP_proxy(ssl, "127.0.0.1:8423" , &SPP_Callback, ssl_next);


			//*this fakes the callback and the data...
			//SSL* fake_ssl = (fake_SPP_connection(ssl));
			//ssl_next = &fake_ssl;

			#ifdef DEBUG
			printf("[middlebox] SPP_proxy done, staring data handlers \n");
			#endif
			handle_data(ssl, *ssl_next);

			// Close socket
    		close(s);
 
		}
	}
	
	// Clean context
	destroy_ctx(ctx);
	
	// Exit
	exit(0);
  }
