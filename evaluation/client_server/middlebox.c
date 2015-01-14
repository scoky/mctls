// A simple https server orginally provided by Ilias

#include "common.h"
#define KEYFILE "server.pem"
#define PASSWORD "password"
#define DHFILE "dh1024.pem"
#include <openssl/e_os2.h>

#define DEBUG
#define MIDDLEBOX_PORT 8423
 
int tcp_listen(int port)
  {
    int sock;
    struct sockaddr_in sin;
    int val=1;


    if((sock=socket(AF_INET,SOCK_STREAM,0))<0)
      err_exit("Couldn't make socket");
    
    memset(&sin,0,sizeof(sin));
    sin.sin_addr.s_addr=INADDR_ANY;
    sin.sin_family=AF_INET;
    sin.sin_port=htons(port);
    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,
      &val,sizeof(val));
    
    if(bind(sock,(struct sockaddr *)&sin,
      sizeof(sin))<0)
      berr_exit("Couldn't bind");
    listen(sock,5);  

    #ifdef DEBUG
	printf("Listening at port: %d\n", port); 
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
	printf("Host %s resolved to %s port %d\n",  host,  hp->h_addr_list[0], port);
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




//this creates a new outgoing SSL connection. If method = SSL it also runs SSL_connect
SSL* create_SSL_connection(char *address, char* method){
	#ifdef DEBUG
    printf("Creating new ssl/spp conection to: %s\n", address);
    #endif

	SSL_CTX *ctx;							// SSL context
	SSL *new_ssl;								// SSL context
	BIO *sbio;								// ?
	int sock;								// socket
	char* ipv4 = strtok(strdup(address), ":");	// ip
    int port = atoi(strtok(NULL, ":"));	// port 


    #ifdef DEBUG
    printf("Connecting to next hop: %s %d\n", ipv4, port);
    #endif

	ctx = initialize_ctx(KEYFILE, PASSWORD, method);
	new_ssl = SSL_new(ctx);
	sock = tcp_connect(ipv4, port);
	sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(new_ssl, sbio, sbio);

    //also run connect for ssl (we do not run this when the callback is used for SPP)
    if (strcmp(method, "ssl")==0)
    {
    	#ifdef DEBUG
    	printf("SSL CONNECT\n");
    	#endif
    	if(SSL_connect(new_ssl) <= 0)
			berr_exit("SSL connect error");
    	#ifdef DEBUG
    	printf("SSL CONNECTED\n");
    	#endif

    }

    return new_ssl;
}





/*
TODO: replace the content of this with the call to the function above (create_SSL_connection)
*/

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

	ctx = initialize_ctx(KEYFILE, PASSWORD, "middlebox");
	new_ssl = SSL_new(ctx);
	sock = tcp_connect(ipv4, port);
	sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(new_ssl, sbio, sbio);

    #ifdef DEBUG
    printf("Connected to next hop...: %s %d\n", ipv4, port);
    #endif

    return new_ssl;
}





int shut_down_connections(SSL* ssl)
{
	int r;
	int socket;

	#ifdef DEBUG
	printf("[middlebox ] Shutting down  connection!\n");
	#endif


	// Shutdown SSL - TO DO (check what happens here) 


	r = SSL_shutdown(ssl);
	if (r == 0)
	{
		shutdown(SSL_get_fd(ssl), SHUT_WR);
		r = SSL_shutdown(ssl);
	}
	// Verify that all went good 
	switch(r){  
		case 1:
		 	printf("Closed  connection \n");
       		break; // Success
		case 0:
		case -1:
		default: // Error 
			printf("[middlebox-p] Shutdown failed\n");
	}

	socket =  SSL_get_fd(ssl);
	close(socket);
    
    return 0;
}



int handle_previous_hop_data(SSL* prev_ssl, SSL* next_ssl, char* proto)
{  
	
    int r,w, status; 
	char buf[BUFSIZZ];
	SPP_SLICE *slice;       
	SPP_CTX *ctx;   


	// Read HTTP GET (assuming a single read is enough)
	while(1){


		#ifdef DEBUG
		printf("[middlebox-p] Waiting to read data from previous hop\n");
		#endif



		if (strcmp(proto, "spp") == 0)
		{        
			r = SPP_read_record(prev_ssl, buf, BUFSIZZ, &slice, &ctx);
			fprintf(stderr, "[middlebox-p] Read %d bytes from previous hop\n", r);
		}
		else 
		{
			r = SSL_read(prev_ssl, buf, BUFSIZZ);
		}


		status = SSL_get_error(prev_ssl, r);
		if (status ==  SSL_ERROR_ZERO_RETURN || status ==  SSL_ERROR_SYSCALL ){
			#ifdef DEBUG
			fprintf(stderr, "[middlebox-p] Connection with previous hop closed, exiting next hop thread\n");
			#endif
			break;
		}
		else if  (status != SSL_ERROR_NONE){
			berr_exit("[middlebox-p] SSL read problem");
		}

		
		#ifdef DEBUG
		printf("[middlebox-p] Data received (from previous hop) (length %d bytes):\n*****\n", r); 
		fwrite(buf, 1, r, stdout);
		printf("\n******\n"); 
		printf("[middlebox-p] Forwarding record to  next hop\n"); 
		#endif

		if (strcmp(proto, "spp") == 0) {
			//w = SPP_write_record(next_ssl, buf, r, next_ssl->slices[0]);
			w = SPP_forward_record(next_ssl, buf,r , slice, ctx, 0);
			check_SSL_write_error(next_ssl, w, r); 
		}
		else
		{
			w = SSL_write(next_ssl, buf, r);
			check_SSL_write_error(next_ssl, w, r); 
		}

		//Look for the blank line that signals the end of the HTTP header
		if(r == 0 ){
			break; 
		}
	}

	//shut_down_connections(prev_ssl);
	SSL_free(prev_ssl);
	// All good 
    return(0);
}


int handle_next_hop_data(SSL* prev_ssl, SSL* next_ssl, char* proto)
{  
    int r,w,status ; 
	char buf[BUFSIZZ];
	SPP_SLICE *slice;       
	SPP_CTX *ctx; 
	// Read HTTP GET (assuming a single read is enough)
	while(1){
		#ifdef DEBUG
		printf("[middlebox-n] Waiting to read data from next hop\n");
		#endif

		if (strcmp(proto, "spp") == 0)
		{
			r = SPP_read_record(next_ssl, buf, BUFSIZZ, &slice, &ctx);
			fprintf(stderr, "[middlebox-p] Read %d bytes from next hop\n", r);
		}
		else 
		{
			r = SSL_read(next_ssl, buf, BUFSIZZ);
		}


		status = SSL_get_error(next_ssl, r);
		if (status ==  SSL_ERROR_ZERO_RETURN || status ==  SSL_ERROR_SYSCALL ){
			#ifdef DEBUG
			fprintf(stderr, "[middlebox-n] Connection with next hop closed, exiting next hop thread\n");
			#endif
			break;
		}
		else if  (status != SSL_ERROR_NONE){
			berr_exit("[middlebox-n] SSL read problem");
		}

		
		#ifdef DEBUG
		printf("[middlebox-p] Data received (from previous hop) (length %d bytes):\n*****\n", r); 
		fwrite(buf, 1, r, stdout);
		printf("\n******\n"); 
		printf("[middlebox-n] Forwarding record to  previous hop\n"); 
		#endif

		if (strcmp(proto, "spp") == 0) {
			w = SPP_forward_record(prev_ssl, buf,r , slice, ctx, 0);
			check_SSL_write_error(prev_ssl, w, r); 
		}
		else
		{
			w = SSL_write(prev_ssl, buf, r);
			check_SSL_write_error(prev_ssl, w, r); 
		}



		// End of socket....
		if(r == 0 ){
			break; 
		}
	}
	//shut_down_connections(next_ssl);
	SSL_free(next_ssl);
	#ifdef DEBUG
	fprintf(stderr, "[middlebox-n] Triggering connection with previous hop to close too\n");
	#endif
	shut_down_connections(prev_ssl);
	// All good 
    return(0);
}





int handle_data(SSL* prev_ssl, SSL* next_ssl, char* proto)
{
	pid_t next_handler;
	int status;

	#ifdef DEBUG
	printf("[middlebox] Initializing data handlers\n");
	#endif

	next_handler = fork();
	if( next_handler == 0) 
	{
		//child process
		// handle traffic from client
		handle_previous_hop_data(prev_ssl, next_ssl, proto);
		#ifdef DEBUG
		printf("[middlebox] Exiting previous hop handler\n");
		#endif
		//TODO: wait for child before returning
		exit(0);
	}
	else 
	{
		//parent 
		handle_next_hop_data(prev_ssl, next_ssl, proto);
		#ifdef DEBUG
		printf("[middlebox] Exiting next hop handler\n");
		#endif
	}

	#ifdef DEBUG
	printf("[middlebox] Waiting previous hop handler to quit before quiting data handler\n");
	#endif

	wait(&status);

	#ifdef DEBUG
	printf("[middlebox] Exiting data handler!\n");
	#endif
	return 0;
}





// Usage function 
void usage(void){
	printf("usage: wclient -c -a \n"); 
	printf("-c:   protocol chosen (ssl ; spp)\n"); 
	printf("-a:   {for ssl splitting only: address to forward in ip:port format}\n");
	printf("-p:   {port number that the box will listen at (default 8423)}\n");
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
	int port = 8423;
	extern char *optarg;                // user input parameters
	char *address_to_forward = NULL;
	int c;  
	proto = "spp";

	// Handle user input parameters
	while((c = getopt(argc, argv, "c:a:p:")) != -1){
			
			switch(c){
			// Protocol chosen
			case 'c':
				if(! (proto = strdup(optarg) ))
					err_exit("Out of memory");
				break; 
			
			// File requested for HTTP GET
			case 'a':
				if(! (address_to_forward = strdup(optarg) ))
					err_exit("Out of memory");
				break; 
						// Client/Server behavior 
			case 'p':
					if(! (port = atoi(optarg) ))
					err_exit("A port NUMBER for the middlebox should be given\n");
				break;
	
			// default case 
			default:
				usage(); 
				break; 
		}
    }

	if ((strcmp(proto, "spp") != 0) && (strcmp(proto, "ssl") != 0))
	{
		printf("Protocol type specified is not supported. Supported protocols are: spp, ssl\n"); 
		usage(); 
	}
	else if ( strcmp(proto, "ssl") == 0  && address_to_forward == NULL )
	{
		printf("You must specify a forwarding address for SSL splitting (-a)\n"); 
		usage(); 
	}
	


	//initialize SSL connection
	if (strcmp(proto, "spp") == 0)
		ctx = initialize_ctx(KEYFILE, PASSWORD, "middlebox");
	else 
		ctx = initialize_ctx(KEYFILE, PASSWORD, "ssl");

	load_dh_params(ctx,DHFILE);
   
	// Socket in listen state
	sock = tcp_listen(port);

	while(1){
		if((s = accept(sock, 0, 0)) < 0){
			err_exit("Problem socket accept\n");
		}
		// fork a new proces 
		if((pid = fork())){
			close(s);
			exit(0);
		} else {
			sbio = BIO_new_socket(s, BIO_NOCLOSE);
			ssl = SSL_new(ctx);
			SSL_set_bio(ssl, sbio, sbio);


			SSL* ssl_next = NULL;

			if (strcmp(proto, "spp") == 0)
			{

				SSL* (*connect_func)(SSL *, char *)  = SPP_Callback;
				char *prxy_address = strdup("127.0.0.1:8423");
				if ((r = SPP_proxy(ssl, prxy_address, connect_func, &ssl_next)) <= 0) {
					berr_exit("[middlebox] SPP proxy error");
				} else {
					#ifdef DEBUG            
	                printf("[middlebox] SPP proxy OK\n"); 
	                #endif
				}
			}
			else if (strcmp(proto, "ssl") == 0)
			{
				if((r = SSL_accept(ssl) <= 0)){
					berr_exit("SSL accept error");
				} else {
					#ifdef DEBUG		
					printf("SSL accept OK\n"); 
					#endif
				}

				SSL* new_connection = create_SSL_connection(address_to_forward, "ssl");
				ssl_next = &new_connection;
			}

			handle_data(ssl, ssl_next, proto);

			// Close socket and exit child thread
    		close(s);
    		
 
		}
	}
	
	// Clean context
	destroy_ctx(ctx);
	
	// Exit
	exit(0);
  }
