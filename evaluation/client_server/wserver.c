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
#define KEYFILE "server.pem"
#define PASSWORD "password"
#define DHFILE "dh1024.pem"
#include <openssl/e_os2.h>

#define DEBUG

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

// 
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

// Send a resonse (SSL and SPP) 
void sendData(SSL *ssl, char *request, char *proto){

	int request_len; 
	int i, r;  

	request_len = strlen(request);
	if (strcmp(proto, "spp") == 0){
		for (i = 0; i < ssl->slices_len; i++){
			#ifdef DEBUG
			printf("[sendData] Write record with slice [%d ; %s]\n", ssl->slices[i]->slice_id, ssl->slices[i]->purpose); 
			#endif
			// currently writing same record -- differentiate per record in the future
			r = SPP_write_record(ssl, request, request_len, ssl->slices[i]);
			check_SSL_write_error(ssl, r, request_len);
		}
	}
	if (strcmp(proto, "ssl") == 0){
		r = SSL_write(ssl, request, request_len); 
		check_SSL_write_error(ssl, r, request_len);
	}
}

// Simple test for SPP handshake 
static int test_SPP(SSL *ssl, int s, char *proto){

	int N_proxies, N_slices, i; 

	#ifdef DEBUG
	printf("[DEBUG] test_SPP called\n"); 
	#endif 	
	
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

	// put 200 OK on the wire 
	char *data = "HTTP/1.0 200 OK\r\n"; 
	sendData(ssl, data, proto); 

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
			berr_exit("Shutdown failed");
	}

	// free SSL 
    SSL_free(ssl);
	
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

// Serve a file -- solution extracted from original s_client (modified not to use BIO)
// TO DO -- extend for SPP (questions...) 
int serveFile(SSL *ssl, char *filename, char *proto){ 
	
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
		sendData(ssl, data, proto); 
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
			printf("Done reading file %s\n", filename); 	
			#endif
			break; 
		}else{
			#ifdef DEBUG
			printf("Read %d bytes from file\n", toSend); 	
			#endif
		}

		/* Verbose logging for debug 
		#ifdef DEBUG
		printf("Content read is:\n%s\n", buf); 	
		printf("Result from fread is: %d\n", i); 	
		#endif
		*/

		// Update how much content is still to send 
		still_to_send -= (i * toSend);
		
		// Send <<buf>> on SPP/SSL connection 
		if (strcmp(proto, "spp") == 0){
			sendData(ssl, buf, proto); 
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
static int http_serve_new(SSL *ssl, int s, char *proto){
  
	char *data; 
    int r; 
	char buf[BUFSIZZ];
	char *filename = "pippo.html"; 

	// Read HTTP GET (assuming a single read is enough)
	while(1){
		if (strcmp(proto, "spp") == 0){
			SPP_SLICE *slice;       
			SPP_CTX *ctx;           
			r = SPP_read_record(ssl, buf, BUFSIZZ, &slice, &ctx);
		}
	
		if (strcmp(proto, "ssl") == 0){
			r = SSL_read(ssl, buf, BUFSIZZ);
		}

		if (SSL_get_error(ssl, r) == SSL_ERROR_NONE){
		} else {
			berr_exit("SSL read problem");
		}
		
		#ifdef DEBUG
		printf("Request received:\n"); 
		printf("%s\n", buf); 
		#endif

		//Look for the blank line that signals the end of the HTTP header
		if(strstr(buf, "\r\n") || strstr(buf, "\n")){
			break; 
		}
	}

	// Parse filename from HTTP GET
	filename = parse_http_get(buf); 

	// Put 200 OK on the wire 
	data = "HTTP/1.0 200 OK\r\n"; 
	sendData(ssl, data, proto); 

	/* Put server name on the wire
	data = "Server: Svarvel\r\n\n"; 
	sendData(ssl, data, proto); 

	// Line for test page
	data = "Server test page\r\n"; 
	sendData(ssl, data, proto); 
	*/

	// Serve requested file 
	serveFile(ssl, filename, proto); 
	// Shutdown SSL - TO DO (check what happens here) 
	r = SSL_shutdown(ssl);
	if( !r ){
    /* If we called SSL_shutdown() first then
         we always get return value of '0'. In
         this case, try again, but first send a
         TCP FIN to trigger the other side's
         close_notify */
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
			berr_exit("Shutdown failed");
	}

	// free SSL 
    SSL_free(ssl);
	
	// Close socket
    close(s);

	// All good 
    return(0);
}


// SSL http serve
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
	printf("-c:   protocol requested: ssl, spp.\n");
	printf("-t:   {1=test handshake ; 0=data delivery}\n");
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
	char *proto;                        //protocol type 
	extern char *optarg;                // user input parameters
	int c;                              // user iput from getopt
	int temp;	 
	bool testing = true;                // testing 200OK vs data delivery 
	bool handshake_only = false;        // testing handhshake only (s_time)

	// Handle user input parameters
	while((c = getopt(argc, argv, "c:t:o:")) != -1){
		switch(c){
			// Protocol 
			case 'c':
				if(! (proto = strdup(optarg) )){
					err_exit("Out of memory");
				}
				break; 

			// Testing choice
			case 't':
				temp = atoi(optarg); 
				testing = (temp == 1 ? true : false);
				break; 
		
			// Handshake only (integrate with above and extend)
			case 'o':
				temp = atoi(optarg); 
				handshake_only = (temp == 1 ? true : false);
				break; 
			}
	}

	// Check that input parameters are correct 
	#ifdef DEBUG
	printf("[DEBUG] Parameters count: %d\n", argc);
	printf("[DEBUG] proto=%s ; testing=%s handshake_only=%s\n", proto, testing ? "true" : "false", handshake_only ? "true" : "false");
	#endif 
	if (argc == 1){
		usage();
	}

	// Build SSL context
	ctx = initialize_ctx(KEYFILE, PASSWORD, proto);
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
    
			// Serve some content here  (SPP)
			if (! handshake_only){
				if (strcmp(proto, "spp") == 0){ 
					if (testing){
						test_SPP(ssl, s, proto);
					}else{
						http_serve_new(ssl, s, proto);
					}
				} 
			
				// Serve some content here  (SSL)
				if (strcmp(proto, "ssl") == 0){ 
					http_serve_new(ssl, s, proto);
				}
			}
	
			// exit from process forked
			exit(0);
		}
	}
	
	// Clean context
	destroy_ctx(ctx);
	
	// Exit
	exit(0);
  }
