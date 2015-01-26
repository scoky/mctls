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
 *   Matteo Varvello <matteo.varvello@telefonica.com> et al. 
 *
 * Description: 
 * An SSL/SPP server. 
 */


#include "common.h"
#include <stdbool.h>            
#include <time.h>
#define KEYFILE "server.pem"
#define PASSWORD "password"
#define DHFILE "dh1024.pem"
#include <openssl/e_os2.h>
//#define DEBUG
#define MAX_PACKET 16384 

static char *strategy = "uni";
static int disable_nagle = 0; //default is disabled

// Listen TCP socket
int tcp_listen(){
    
	int sock;
	struct sockaddr_in sin;
	int val = 1;

	// Create socket, allocate memory and set sock options
	if((sock=socket(AF_INET,SOCK_STREAM,0)) < 0){
		err_exit("Couldn't make socket");
	}
    memset(&sin, 0, sizeof(sin));
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT);
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val,sizeof(val));

    if (disable_nagle == 1)
    	set_nagle(sock, 1); 

	// Bind to socket    
	if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
		berr_exit("Couldn't bind");
	}

	// Listen to socket
    listen(sock,5);  

	// Return socket descriptor
    return(sock);
}

// Load parameters from "dh1024.pem"
void load_dh_params(SSL_CTX *ctx, char *file){
	DH *ret=0;
	BIO *bio;

    if ((bio=BIO_new_file(file,"r")) == NULL){
      berr_exit("Couldn't open DH file");
	}

	ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if(SSL_CTX_set_tmp_dh(ctx,ret) < 0){
		berr_exit("Couldn't set DH parameters");
	}
}

// Generate ephemeral RSA key (check DH) 
void generate_eph_rsa_key(ctx)
  SSL_CTX *ctx;
  {
    RSA *rsa;

    rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);
    
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
	printf ("[DEBUG] File requested is <<%s>> with size <<%d bytes>>\n", filename, sz); 
	#endif 
	return sz; 
}

// Function to print a prox list
void print_proxy_list(SPP_PROXY **proxies, int N){
	int i; 

	#ifdef DEBUG
	printf("[DEBUG] Print proxy list (There are %d available proxies)\r\n", N);
	#endif

	// Iterate through list 
	for (i = 0; i < N; i++){
		printf("Proxy %d -- %s\r\n", i, proxies[i]->address);
	}
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

// splitting 
void splitting (SSL *ssl, char *request, int request_len){
	int beginIndex = 0, i, inc, usedSlices; 

	// For client/server strategy just use half slices 	
	if (strcmp(strategy, "cs") == 0){
		 usedSlices = ssl->slices_len / 2; 
	} else{
		 usedSlices = ssl->slices_len; 
	}

	// Compute increment 
	inc = request_len / (usedSlices); 
	
	// Slicing happens here  
	for (i = 0; i < usedSlices; i++){
		
		char* dest = (char*) malloc(inc); 
		#ifdef DEBUG
		printf("[DEBUG] Write sub-record with slice [%d ; %s]. (strategy <<%s>>)\n"\
			"[DEBUG] Sub-record size is %d (beginIndex=%d -- endIndex=%d)\n", \
			ssl->slices[i]->slice_id, ssl->slices[i]->purpose, strategy, inc, beginIndex, (beginIndex + inc)); 
		#endif
    	memset(dest, 0, inc);
		memcpy(dest, request + beginIndex,  inc); 
		#ifdef DEBUG
		printf("%s\n", dest); 
		#endif 
		int r = SPP_write_record(ssl, dest, inc, ssl->slices[i]);
		#ifdef DEBUG
		printf("Wrote %d bytes\n", r);
		#endif
		check_SSL_write_error(ssl, r, inc);
		
		// Move pointers
		beginIndex += inc;

		// Increase pointer for last slice  
		if ( i == (usedSlices - 2)){
			inc = request_len - beginIndex; 
		} 
	
		// free memory 
		free (dest); 
	}
}

// Send some data (SSL and SPP) 
void sendData(SSL *ssl, int s, char *request, char *proto, int request_len){

	int r; 

	//mmmm  
	//request_len--; 

	// logging
	#ifdef DEBUG
	printf("[DEBUG] sendData with length %d\n", request_len); 
	#endif 
	
	// SPP
	if (strcmp(proto, "spp") == 0){
		// TO DO implement further splitting here 
		splitting(ssl, request, request_len); 
	}	
	// SSL
	else if (strcmp(proto, "ssl") == 0){
		r = SSL_write(ssl, request, request_len); 
		check_SSL_write_error(ssl, r, request_len);
	}
	else if (strcmp(proto, "pln") == 0){
		r = write(s, request, request_len); 
	}

}

// Simple test for SPP handshake 
static int http_simple_response(SSL *ssl, int s, char *proto){

	int i; 

	#ifdef DEBUG
	printf("[DEBUG] HTTP test simple response\n"); 
	#endif 	
	
	#ifdef DEBUG
	printf("[DEBUG] Verify proxies and slices were correctly received\n"); 

	if (strcmp(proto, "spp") == 0){
		// Print proxies
		for (i = 0; i < ssl->proxies_len; i++){
			printf("\t[DEBUG] Proxy: %s\n", ssl->proxies[i]->address); 
		}

		// print slices
		for (i = 0; i < ssl->slices_len; i++){
			printf("\t[DEBUG] Slice with ID %d and purpose %s\n", ssl->slices[i]->slice_id, ssl->slices[i]->purpose); 
		}
	}
	#endif 

	// put 200 OK on the wire 
	char *data = "HTTP/1.0 200 OK\r\n"; 
	int request_len = strlen(data);
	sendData(ssl, s,  data, proto, request_len); 

	if (strcmp(proto, "pln") != 0)
	{
		// Shutdown SSL - TO DO (check what happens here) 
		int r = SSL_shutdown(ssl);
		if( !r ){
			shutdown(s, 1);
			r = SSL_shutdown(ssl);
	    }

		// Verify that shutdown was good 
		switch(r){  
			case 1:
	       		break; // Success
			case 0:
			case -1:
			default: // Error 
				#ifdef DEBUG 
				printf ("Shutdown failed with code %d\n", r); 
				#endif 
				berr_exit("Shutdown failed");
		}
		// free SSL 
	    SSL_free(ssl);
	}
	
	// All good	
	return 0; 
}


// Parse HTTP GET request to get filename 
char* parse_http_get(char *buf){ 

	char *delim="\r\n"; 
	char *token = strtok(buf , delim);   
	delim=" "; 
	char *fn = strtok(token, delim);   
	fn = strtok(NULL, delim);   
	return fn; 
}

// Serve a given amount of data 
int serveData(SSL *ssl, int s,  int data_size, char *proto){ 
	
	// Logging
	#ifdef DEBUG
	printf ("[DEBUG] Requested data with size %d\n", data_size); 
	#endif 
	// Send data via SPP/SSL
	int still_to_send = data_size; 
	for (;;){
		// Derive min between how much to send and max buffer size 
		int toSend = BUFTLS; 
		if (still_to_send < toSend){
			toSend = still_to_send; 
		}

		//Allocate buffer with size to send and fill with "!"
		char *buf = (char*) malloc(sizeof(char) * toSend);
		memset(buf, '!', sizeof(char) * toSend);	
		#ifdef VERBOSE
		printf ("[DEBUG] Buffer=\n%s\n", buf); 
		#endif 
		
		// Send <<buf>> on SPP/SSL connection 
		if (strcmp(proto, "spp") == 0){
			sendData(ssl, s, buf, proto, sizeof(char) * toSend); 
		}
		if (strcmp(proto, "ssl") == 0){
			int r = SSL_write(ssl, buf, toSend);
			check_SSL_write_error(ssl, r, toSend);
		}
		if (strcmp(proto, "pln") == 0){
			sendData(ssl, s, buf, proto, sizeof(char) * toSend); 
		}
		
		// Update how much content is still to send 
		still_to_send -= toSend;
		if (still_to_send == 0){
			#ifdef DEBUG
			printf ("[DEBUG] No more data to send\n"); 
			#endif 
			break; 	
		}

		// Free buffer
		free(buf); 
	}

	// All good
	return 0; 
}	

// Serve a file -- solution extracted from original s_client 
// NOTES: (1) modified not to use BIO ; (2) re-negotiation currently not used
int serveFile(SSL *ssl, int s, char *filename, char *proto){ 
	
 	FILE *fp;				// file descriptot 
	int file_size = 0;		// size of file being sent 
 
	// Open requested file for reading
 	if ((fp = fopen(filename,"r")) == NULL){
		#ifdef DEBUG
		printf ("File <<%s>> do not exist\n", filename); 
		#endif 
		char *data = "Error opening file\r\n"; 
		int request_len = strlen(data);
		sendData(ssl, s, data, proto, request_len); 
		fclose(fp); 
		return -1; 
	}else{
		// Calculate file size 
		// Seek  to the end of the file and ask for position 
		fseek(fp, 0L, SEEK_END);
		file_size = ftell(fp);
		// Seek to the beginning of the file 
		fseek(fp, 0L, SEEK_SET);
		
		#ifdef DEBUG
		printf ("[DEBUG] File requested is <<%s>> with size <<%d bytes>>\n", filename, file_size); 
		#endif 
	}

	// Allocate buffer for data to send 
	char* buf = (char*) malloc (file_size); 
	
	// Read "toSend" content from file 
	int i = fread(buf, file_size, 1, fp);

	// Check for end of file
	if (i <= 0){
		#ifdef DEBUG
		printf("[DEBUG] Done reading file %s\n", filename); 	
		#endif
	}else{
		#ifdef DEBUG
		printf("[DEBUG] Still some data to read? (read result = %d)\n", i); 	
		#endif
	}

	// Send <<buf>> on SPP/SSL connection 
	sendData(ssl, s, buf, proto, file_size); 
		
	// Close file
	fclose(fp); 

	// All good
	return 0; 
}	



// Serve a file -- solution extracted from original s_client 
// NOTES: (1) modified not to use BIO ; (2) re-negotiation currently not used
int serveFile_old(SSL *ssl, int s, char *filename, char *proto){ 
	
 	FILE *fp;				// file descriptot 
	char buf[BUFSIZZ];		// buffer for data to send
	int file_size = 0;		// size of file being sent 
	int still_to_send; 		// amount of data from file still to be sent 
 
	// Open requested file for reading
 	if ((fp = fopen(filename,"r")) == NULL){
		#ifdef DEBUG
		printf ("File <<%s>> do not exist\n", filename); 
		#endif 
		char *data = "Error opening file\r\n"; 
		int request_len = strlen(data);
		sendData(ssl, s, data, proto, request_len); 
		fclose(fp); 
		return -1; 
	}else{
		// Calculate file size 
		// Seek  to the end of the file and ask for position 
		fseek(fp, 0L, SEEK_END);
		file_size = ftell(fp);
		// Seek to the beginning of the file 
		fseek(fp, 0L, SEEK_SET);
		
		#ifdef DEBUG
		printf ("[DEBUG] File requested is <<%s>> with size <<%d bytes>>\n", filename, file_size); 
		#endif 
	}

	// Transfer file via SPP/SSL
	still_to_send = file_size; 
	for (;;){
		
		// Derive min between how much to send and max buffer size 
		int toSend = BUFSIZZ; 
		if (still_to_send < toSend){
			toSend = still_to_send; 
		}

		// Read "toSend" content from file 
		int i = fread(buf, toSend, 1, fp);

		// Check for end of file
		if (i <= 0){
			#ifdef DEBUG
			printf("[DEBUG] Done reading file %s\n", filename); 	
			#endif
			break; 
		}else{
			#ifdef DEBUG
			printf("[DEBUG] Read %d bytes from file\n", toSend); 	
			#endif
		}

		// Update how much content is still to send 
		still_to_send -= (i * toSend);
		
		// Send <<buf>> on SPP/SSL connection 
		if (strcmp(proto, "spp") == 0){
			int request_len = strlen(buf);
			sendData(ssl, s, buf, proto, request_len); 
		}
		if (strcmp(proto, "ssl") == 0){
			int r = SSL_write(ssl, buf, toSend);
			check_SSL_write_error(ssl, r, toSend);
		}
	}

	// Close file
	fclose(fp); 

		/* CODE FOR RENOGOTIATION 
		// Check if too many losses 
		if (total_bytes > (3 * file_size)){
			total_bytes = 0;
			fprintf(stderr,"RENEGOTIATE\n");
			SSL_renegotiate(ssl); 
		}
		
		// Renegotiation if too many lossed
		for (j = 0; j < i; ){
			// After 13 attempts, re-negotate at SSL level 
			static int count = 0; 
			if (++count == 13) { 
				SSL_renegotiate(ssl); 
			} 

			int r = SSL_write(ssl, buf, BUFSIZZ);
			check_SSL_write_error(ssl, r, BUFSIZZ);
			//int k = BIO_write(io, &(buf[j]), i-j);
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
    } // end for loop 
	*/
	
	// All good
	return 0; 
}	


// 1) work with both SSL and SPP
// 2) no usage of BIO APIs
static int http_serve_request(SSL *ssl, int s, char *proto, bool shut, int action){
  
    int r; 
	char buf[BUFSIZZ];
	char *filename = ""; 
	int ret_value = 0; 

	// Read HTTP GET (assuming a single read is enough)
	while(1){
		if (strcmp(proto, "spp") == 0){
			SPP_SLICE *slice;       
			SPP_CTX *ctx;           
			r = SPP_read_record(ssl, buf, BUFSIZZ, &slice, &ctx);
			if (SSL_get_error(ssl, r) != SSL_ERROR_NONE)
				berr_exit("[DEBUG] SSL read problem");
			#ifdef DEBUG
			printf("[DEBUG] Read %d bytes\n", r);
			#endif
		}
		else if (strcmp(proto, "ssl") == 0){
			r = SSL_read(ssl, buf, BUFSIZZ);
			if (SSL_get_error(ssl, r) != SSL_ERROR_NONE)
				berr_exit("[DEBUG] SSL read problem");
		}
		else if (strcmp(proto, "pln") == 0){
			r = read(s, buf, BUFSIZZ);
		}

		#ifdef DEBUG
		printf("[DEBUG] Request received:\n"); 
		printf("%s\n", buf); 
		#endif

		//Look for the blank line that signals the end of the HTTP header
		if(strstr(buf, "\r\n") || strstr(buf, "\n")){
			break; 
		}
	}

	// Parse filename from HTTP GET
	filename = parse_http_get(buf); 
	int fSize = atoi(filename);
	if (fSize != 0 || filename[0] == '0'){
		#ifdef DEBUG
		printf("[DEBUG] File requested by size <<%d>>\n", fSize);
		#endif
	} else {
		#ifdef DEBUG
		printf("[DEBUG] File requested by name <<%s>>\n", filename); 
		#endif
	}

	// Simple trick to end 
	if (strcmp(filename, "-1") == 0){
		#ifdef DEBUG
		printf("[DEBUG] Client requested to end session\n");
		#endif 
		ret_value = -1; 
		shut = true;  	
	}else{
		// Serve requested file either by name or by size  
		if (action == 3){
			if (fSize == 0){
				serveFile(ssl, s, filename, proto); 
			} else {
				serveData(ssl, s,  fSize, proto); 
			}
		}
		if (action == 4){
			// convert filename into data size 
			int data_size; 
			sscanf(filename, "%d", &data_size); 

			// serve data with size above 
			serveData(ssl, s,  data_size, proto); 
		}
	}

	// Do not shutdown TLS for browser-like behavior unless requested
	if (shut){
		#ifdef DEBUG
		printf("[DEBUG] Shutdown SSL connection\n");
		#endif 
		// Shutdown SSL - TO DO (check what happens here) 
		r = SSL_shutdown(ssl);
		if( !r ){
			shutdown(s, 1);
			r = SSL_shutdown(ssl);
	    }

		// Verify that all went good 
		switch(r){  
			case 1:
    	   		break; // Success
			case 0:
			case -1:
			default: // Error 
				#ifdef DEBUG 
				printf ("Shutdown failed with code %d\n", r); 
				#endif 
				berr_exit("Shutdown failed");
		}

		// free SSL 
    	SSL_free(ssl);
	
		// Close socket
    	close(s);
	}else{
		#ifdef DEBUG
		printf("[DEBUG] No shutdown since SSL connection might still be used\n");
		#endif
	}
	// All good 
    return ret_value; 
}


// SSL http serve (almost original function) 
static int http_serve_SSL(SSL *ssl, int s){
  
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
				#ifdef DEBUG 
				printf ("Shutdown failed with code %d\n", r); 
				#endif 
				berr_exit("Shutdown failed");
		}
    } // end for loop 

    SSL_free(ssl);
    close(s);

    return(0);
  }

// Usage function 
void usage(void){
	printf("usage: wserver -c -o -s\n");
	printf("-c:   protocol requested: ssl, spp, pln, spp-mod.\n");
	printf("-o:   {1=test handshake ; 2=200 OK ; 3=file transfer ; 4=browser-like behavior}\n");
	printf("-s:   content slicing strategy {uni; cs}\n");
	printf("-l:   duration of load estimation time (10 sec default)\n");
	printf("{uni[DEFAUL]=split response equally among slices ; cs=split uniformly among half slices, assuming other half is used by the client}\n");
	exit(-1);
}


// Main function  
int main(int argc, char **argv){
	int sock, newsock;                 // socket descriptors 
	BIO *sbio;
	SSL_CTX *ctx;
	SSL *ssl;
	int r;
	pid_t pid;
	char *proto;                        // protocol type 
	extern char *optarg;                // user input parameters
	int c;                              // user iput from getopt
	int action = 0;                     // specify client/server behavior (handshake, 200OK, serve file, browser-like) 
	int status;                         // ...
	clock_t start, end;                 // timers for cpu time estimation 
	double cpu_time_used;               // cpu time used 
	int loadTime = 10;                  // time used for load estimation (10 second default, user can change with option -l)

	// Handle user input parameters
	while((c = getopt(argc, argv, "c:o:s:l:")) != -1){
		switch(c){
			// Protocol 
			case 'c':	if(! (proto = strdup(optarg) )){
							err_exit("Out of memory");
						}
						if (strcmp(proto, "fwd") == 0){
							proto = "ssl"; 
						}
						if (strcmp(proto, "spp_mod") == 0){
							proto = "spp"; 
							disable_nagle = 1;
						}
						break; 

			// Client/Server behavior 
			case 'o':	action = atoi(optarg); 
						break; 

			// Control slicing strategy
			case 's':	if(! (strategy = strdup(optarg) )){
							err_exit("Out of memory");
						}
						break;
			// Control load estimation period 
			case 'l':	loadTime = atoi(optarg); 
						break;
		}
	}

	// Check that input parameters are correct 
	if (argc == 1){
		usage();
	}
	if (action < 1 || action > 4){
		usage(); 
	}
	
	// Logging input parameters 
	#ifdef DEBUG
	printf("[DEBUG] Parameters count: %d\n", argc);
	char *temp_str = "undefined"; 
	if (action == 1)
		temp_str = "handshake_only";  
	if (action == 2)
		temp_str = "200_OK";  
	if (action == 3)
		temp_str = "serve_file";  
	if (action == 4)
        temp_str = "browser_like";  
	printf("\t[DEBUG] proto=%s; action=%d (%s)\n", proto, action, temp_str); 
	#endif 

	// Build SSL context
	ctx = initialize_ctx(KEYFILE, PASSWORD, proto);
	load_dh_params(ctx,DHFILE);
   
	// Socket in listen state
	sock = tcp_listen();

	// Wait for client request 
	long finishLoadEst = (long) time (NULL) + loadTime;
	int nConn = 0; 
	bool report = true; 
	while(1){
			
		#ifdef DEBUG
		printf("[DEBUG] Waiting on TCP accept...\n"); 
		#endif
		if((newsock = accept(sock, 0, 0)) < 0){
			err_exit("Problem socket accept\n");
		}else{
			#ifdef DEBUG
			printf("[DEBUG] Accepted new connection %d\n", sock); 
			#endif
		}
		// keep track of number of connections
		nConn++;

		// Fork a new process
		signal(SIGCHLD, SIG_IGN); 
		pid = fork(); 
		if (pid -= 0){
			/* In chil process */
			if (pid == -1) {
				berr_exit("FORK error"); 
				return 1;
           	}
			start = clock();
			#ifdef DEBUG
			printf("[DEBUG] child process close old socket (why?) and operate on new one\n");
			#endif
			close(sock);

			if (strcmp(proto, "pln") != 0) 
			{
				sbio = BIO_new_socket(newsock, BIO_NOCLOSE);
				ssl = SSL_new(ctx);
				SSL_set_bio(ssl, sbio, sbio);
				
				// Wait on SSL Accept 
				if((r = SSL_accept(ssl) <= 0)){
					berr_exit("SSL accept error");
				} else {
					#ifdef DEBUG
					if (strcmp(proto, "ssl") == 0){ 		
						printf("[DEBUG] SSL accept OK\n"); 
					}else{
						printf("[DEBUG] SPP accept OK\n"); 
					}
					#endif
				}
			}
			end = clock();
			cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
			if (loadTime > 0){
				printf( "CPU time=%f sec\n", cpu_time_used); 
			}
  			
			// Switch across possible client-server behavior 
			// NOTE: here we can add more complex strategies
			switch(action){
				// Handshake only 
				case 1: break; 
				
				// Respond with 200 OK
				case 2: http_simple_response(ssl, newsock, proto);
						break; 
				
				// Serve some content 
				case 3: http_serve_request(ssl, newsock, proto, false, action);
						break;
			
				// Serve a browser like behavior 
				// NOTE
				// This can only serve one connection at a time. 
				// Here we would need to fire a new thread 
				// (or re-think the code) to support multiple SSL connections 
				case 4: while(1){
							if (http_serve_request(ssl, newsock, proto, false, action) < 0){
								break; 
							}
						}
						break;

				// Unknown option 
				default: usage();
						 break; 
			}
			// Correctly end child process
			#ifdef DEBUG
			printf("[DEBUG] End child process (prevent zombies)\n");
			#endif
			exit(0);  
			// return 0 
		}else{
			#ifdef DEBUG
			printf("[DEBUG] parent process close new socket (why?)\n");
			#endif
			close(newsock); 
		}
	}
	wait(&status);
	// Clean context
	destroy_ctx(ctx);
	
	// Correctly end parent process
	exit(0); 
}
