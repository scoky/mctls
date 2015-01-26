/* 
 * Copyright (C) Telefonica 2015
 * All rights reserved.
 *
 * Telefonica Proprietary Information.
 *
 * Contains proprietary/trade secret information which is the property of 
 * Telefonica and must not be made available to, or copied or used by
 * anyone outside Telefonica without its written authorization.
 *
 * Authors: 
 *   Ilias Leontiadis <ilias.leontiadis@telefonica.com> et al. 
 *
 * Description: 
 * An SSL/SPP middlebox. 
 */


#include "common.h"
#include <time.h>
#include <stdbool.h>
#define KEYFILE "server.pem"
#define PASSWORD "password"
#define DHFILE "dh1024.pem"
#include <openssl/e_os2.h>
static int disable_nagle  = 0 ;

//#define DEBUG				// now this can be turned on/off in the Makefile 

 
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

    if (disable_nagle == 1)
    	set_nagle(sock, 1); 
    
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

    if (disable_nagle == 1)
    	set_nagle(sock, 1); 

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
	Just creates a new SSL instance but it does not connect !
*/

SSL* SPP_Callback(SSL *ssl, char *address){

	return create_SSL_connection(address, "middlebox");

}




/*
This will terminate but NOT destroy a socket
*/
int shut_down_connections(SSL* ssl)
{
	int r;
	int socket;

	#ifdef DEBUG
	printf("[middlebox ] Shutting down  connection!\n");
	#endif

	//shutdown(SSL_get_fd(ssl), SHUT_WR);
	//shutdown(SSL_get_fd(ssl), 1);
	r = SSL_shutdown(ssl);
	
	if (r == 0)
	{
		#ifdef DEBUG
		printf("[middlebox ] r=0 trying again to shutdown\n");
		#endif
		shutdown(SSL_get_fd(ssl), 1);
		r = SSL_shutdown(ssl);
	}
	
	// Verify that all went good 
	switch(r){  
		case 1:
			#ifdef DEBUG
			printf("[middlebox ] Succesfully shut down client connection!\n");
			#endif
       		break; // Success
		case 0:
		case -1:
		default: // Error 
			printf("[middlebox] Connection shutdown failed\n");
	}

	//socket =  SSL_get_fd(ssl);
	//close(socket);
    
    return 0;
}


/*
Handles data from previous hop and forwards them to the next one. 
TODO: in theory the two handlers can be merged in a single function...
*/

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
		}
		else 
		{
			r = SSL_read(prev_ssl, buf, BUFSIZZ);
		}

		status = SSL_get_error(prev_ssl, r);
		if (status ==  SSL_ERROR_ZERO_RETURN || status ==  SSL_ERROR_SYSCALL ){
			#ifdef DEBUG
			fprintf(stderr, "[middlebox-p] Connection with previous hop closed, exiting previous hop handler\n");
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

		//this is probably not necessary...
		if(r == 0 ){
			break; 
		}
	}

	// NEW SHUT DOWN 
	shut_down_connections(next_ssl);
	// The previous connection has been terminated by the client... we just free the SSL object... 
	//SSL_free(prev_ssl);
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
		}
		else 
		{
			r = SSL_read(next_ssl, buf, BUFSIZZ);
		}

		status = SSL_get_error(next_ssl, r);
		if (status ==  SSL_ERROR_ZERO_RETURN || status ==  SSL_ERROR_SYSCALL ){
			#ifdef DEBUG
			fprintf(stderr, "[middlebox-n] Connection with next hop closed, exiting next hop handler and also closing previous hop connection\n");
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

		// In theory this is not necessary
		if(r == 0 ){
			break; 
		}
	}
	
	
	#ifdef DEBUG
	fprintf(stderr, "[middlebox-n] Triggering connection with previous hop to close too\n");
	#endif
	//SSL_free(prev_ssl);
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


	//CLEAN UP
	close(SSL_get_fd(next_ssl));
	close(SSL_get_fd(prev_ssl));

	//CLEAN UP
	SSL_free(next_ssl);
	//SSL_free(prev_ssl);

	#ifdef DEBUG
	printf("[middlebox] Exiting data handler!\n");
	#endif
	return 0;
}


int tcp_forwarder(int prev, int next)
{
	pid_t next_handler;
	int status;
	char buf[BUFSIZZ];
	int r;

	#ifdef DEBUG
	printf("[middlebox] Initializing data handlers\n");
	#endif

	next_handler = fork();
	if( next_handler == 0) 
	{
		//child process
		// handle traffic from client
		while(1){
 		r = read( prev, buf, sizeof( buf ) );
		#ifdef DEBUG
		printf("[middlebox-forwarder] Data received (from previous hop) (length %d bytes)\n", r); 
		#endif
	    if ( r <= 0 )
			break;
	    r = write( next, buf, r );
	    if ( r <= 0 )
			break;
		}
		close(next);
		exit(0);
	}
	else 
	{
		//parent 
		while(1){
 		r = read( next, buf, sizeof( buf ) );
 		#ifdef DEBUG
		printf("[middlebox-forwarder] Data received (from next hop) (length %d bytes)\n", r); 
		#endif
	    if ( r <= 0 )
			break;
	    r = write( prev, buf, r );
	    if ( r <= 0 )
			break;
		}
		
		//this will signal the other thread to quit
		close(prev);
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
	printf("usage: mbox -c -a -p -m\n"); 
	printf("-c:   protocol chosen (ssl ; spp; fwd; pln)\n"); 
	printf("-a:   {for ssl splitting only: address to forward in ip:port format}\n");
	printf("-p:   {port number that the box will listen at (default 8423)}\n");
	printf("-m:   {id of this proxy in ip:port format.}\n");
	printf("-l:   duration of load estimation time (10 sec default)\n");
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
	char *prxy_address = "127.0.0.1:8423";
	SSL* ssl_next = NULL;
    clock_t start, end;
    double cpu_time_used; 
	int loadTime = 0;                  // time used for load estimation (not used but for future. 0 means no printing)
	
	// Handle user input parameters
	while((c = getopt(argc, argv, "h:c:a:p:m:l:")) != -1){
			
			switch(c){

			// Print usage
			case 'h':	usage(); 
						break; 

			// Protocol chosen
			case 'c':	if(! (proto = strdup(optarg) )){
							err_exit("Out of memory");
						}
						if (strcmp(proto, "spp_mod") == 0){ 
							proto = "spp"; 
							set_nagle = 1;
						}   
						if (strcmp(proto, "pln") == 0){ 
							proto = "fwd"; 
						}  
						break; 
			
			// Address to forward in case of SSL splitting 
			case 'a':	if(! (address_to_forward = strdup(optarg) )){
							err_exit("Out of memory");
						}
						break; 
			
			// Port used by mbox 
			case 'p':	if(! (port = atoi(optarg) )){
							err_exit("A port NUMBER for the middlebox should be given\n");
						}
						break;
										
			// Middlebox ID, required by SPP
			case 'm':	if(! (prxy_address = strdup(optarg) )){
							err_exit("Out of memory");
						}
						break;
			// Control load estimation period 
			case 'l':   loadTime = atoi(optarg);
						break; 

			// Default case 
			default:	usage(); 
						break; 
		}
    }

	// Checking input parameters 
	if ((strcmp(proto, "spp") != 0) && (strcmp(proto, "ssl") != 0) && (strcmp(proto, "fwd") != 0))
	{
		printf("Protocol type specified is not supported. Supported protocols are: spp, ssl, fwd\n"); 
		usage(); 
	}
	else if ( (strcmp(proto, "ssl") == 0 || (strcmp(proto, "fwd"))==0 ) && address_to_forward == NULL )
	{
		printf("You must specify a forwarding address for SSL splitting or forwarding  (-a)\n"); 
		usage(); 
	}
	
	//logging 
	#ifdef DEBUG
	printf("[DEBUG] port=%d proto=%s address_to_fwd=%s  prxy_address=%s\n", port, proto, address_to_forward, prxy_address);  
	#endif 
	
	//initialize SSL connection
	if (strcmp(proto, "fwd") != 0){
		if (strcmp(proto, "spp") == 0)
			ctx = initialize_ctx(KEYFILE, PASSWORD, "middlebox");
		else 
			ctx = initialize_ctx(KEYFILE, PASSWORD, "ssl");

		load_dh_params(ctx,DHFILE);
	}
   
	// Socket in listen state
	sock = tcp_listen(port);

	// Wait for client request 
	int nConn = 0;
	while(1){
		// keep track of number of connections
		nConn++; 

		if((s = accept(sock, 0, 0)) < 0){
			err_exit("Problem socket accept\n");
		}
		signal(SIGCHLD, SIG_IGN);
		// fork a new proces 
		if((pid = fork())){
			close(s);
		} else {
			// start timer for CPU time on first connection 
			start = clock();

			if (strcmp(proto, "fwd") == 0){
				#ifdef DEBUG            
		        printf("[middlebox] TCP forwarder\n"); 
		        #endif
				/* no encryption... just tcp forwarding... */
				char* fwd_host = strtok(strdup(address_to_forward), ":");	// TODO: memory leak here...
    			int fwd_port = atoi(strtok(NULL, ":"));	// port 
				int next_hop =  tcp_connect(fwd_host, fwd_port);
				tcp_forwarder(s, next_hop);
			} else {
				sbio = BIO_new_socket(s, BIO_NOCLOSE);
				ssl = SSL_new(ctx);
				SSL_set_bio(ssl, sbio, sbio);

				// Accept connections based on the protocol (ssl split or proxy)
				if (strcmp(proto, "spp") == 0)
				{
					//SSL* (*connect_func)(SSL *, char *)  = SPP_Callback;
					if ((r = SPP_proxy(ssl, prxy_address, SPP_Callback, &ssl_next)) <= 0) {
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
					ssl_next = create_SSL_connection(address_to_forward, "ssl");
				}
				/*
				STARTING THE DATA HANDLERS
				*/
				handle_data(ssl, ssl_next, proto);
			}
			// Close socket
    		close(s);
    	
			// Compute CPU time user for this connection and log it 
			end = clock();
			cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
			if (loadTime > 0){
				printf("CPU time=%f sec\n", cpu_time_used); 
			}		
			// Exit child thread
			exit(0);
		}
	}
	
	// Clean context
	destroy_ctx(ctx);
	
	// Exit
	exit(0);
  }
