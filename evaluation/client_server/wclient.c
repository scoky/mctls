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
 * An SSL/SPP client that connects to an SSL/SPP through a bunch of 
 * proxies. 
 */

#include <stdbool.h>            // to support boolean
#include "common.h"				// common library between client and server
#include <pthread.h>            // thread support
#define KEYFILE "client.pem"    // client certificate
#define PASSWORD "password"     // unused now 	
#define DEBUG                   // verbose logging
#define CONNECT_TIMEOUT 5       // socket connection timeout 
#define MAX_CONC_CLIENT 100     // max concurrent clients

static char *host=HOST;
static int port=PORT;
static int require_server_auth = 1;
static int clientID=0; 

// -- Moved up here just because of thread 
static SSL *ssl;                              // SSL instance
static char *proto = "ssl";                   // protocol to use (ssl ; spp)  



// Read counter of number of proxies in the provided list 
int read_proxy_count(char *file_name){
	FILE *fp;					// pointer to file
	int N; 						// number of proxies 
	char line [128];			// maximum size of line to read from 

	// Open file for reading
	fp = fopen(file_name,"r");	
   
	// CHheck for errors while opening file
	if( fp == NULL ){
		printf("Error while opening file %s.\r\n", file_name);
		exit(-1);
    }

	// Read first line of file
	fgets ( line, sizeof line, fp ); 
	
	// Convert char into integer 
	N = line[0] - '0';
	#ifdef DEBUG
	printf("[DEBUG] Expected number of proxies is: %d\r\n", N);
	#endif
	
	// Close file
	fclose(fp);

	return N; 
}

		
// Function to read a proxy list from file and populate array of proxies
void read_proxy_list(char *file_name, SPP_PROXY **proxies, SSL *ssl){
   	FILE *fp;					// pointer to file
	int count = 0;				// simple counters
	bool firstLine = 1; 		// flag for first line in file
	char line [128];			// maximum size of line to read from 

	// Open file for reading
	fp = fopen(file_name,"r");	
   
	// Check for errors while opening file
	if( fp == NULL ){
		printf("Error while opening file %s.\r\n", file_name);
		exit(-1);
	}

	// Read file line-by-line
	while ( fgets ( line, sizeof line, fp ) != NULL ) {
	
		// Remove trailing newline (NOTE: strtoK is not thread safe)
		strtok(line, "\n");
		
		// Handle first line as a special case
		if (firstLine){
			firstLine = 0; 
			continue; 
		}
		
		// Generate a proxy from IP address just read 
		char *newLine;  
		newLine = (char *)malloc(strlen(line));    
		strcpy(newLine, line);
		proxies[count] = SPP_generate_proxy(ssl, newLine);
		count++; 
		/*
		#ifdef DEBUG
		printf("Proxy %d stored has address: %s\r\n", count, proxies[count]->address);
		int j; 
		for (j = 0; j < count; j++){
			printf("Previous proxy was %s\r\n",  proxies[j]->address);
		}
		#endif
		*/
	}
	
	// Close file
	fclose(fp);
}

// Print proxy list 
void print_proxy_list(SPP_PROXY **proxies, int N){
	int i; 

	if (N == 1){	
		printf("[DEBUG] There is %d available proxy (the final server):\r\n", N);	
	}else{
		printf("[DEBUG] There are %d available proxies:\r\n", N);	
	}
	for (i = 0; i < N; i++){
		printf("\t[PROXY] Proxy %d with address %s\r\n", i, proxies[i]->address);
	}
}

/*
// Timeout for connect 
static int sTimeout = 0; 

// Handler for alarm raised by TCP connect 
static void AlarmHandler(int sig) { 
  sTimeout = 1; 
}
*/

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
	printf("[DEBUG] Host %s resolved\n", host); 
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
	printf("[DEBUG] Socket correctly created\n"); 
	#endif

	if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0){
		err_exit("Couldn't connect socket");
	}
	#ifdef DEBUG
	printf("[DEBUG] Socket connected\n"); 
	#endif
	
   	/* Check solution below if we need to support a timeout -- to debug  
	signal(SIGALRM, AlarmHandler); 
	sTimeout = 0; 
	alarm(CONNECT_TIMEOUT); 

	if ( connect(sock, (struct sockaddr *) &addr, sizeof(addr)) ){
		if ( sTimeout ){
			err_exit("timeout connecting stream socket"); 
		}
	}
	
	sTimeout = 0; 
	alarm(CONNECT_TIMEOUT); 
	*/
	return sock;
}

/* Check that the common name matches the host name*/
void check_cert(SSL *ssl, char *host){
	X509 *peer;
	char peer_CN[256];
  	
	long res = SSL_get_verify_result(ssl);  
	if ((res == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) || (res == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)){
		#ifdef DEBUG
		printf("[DEBUG] Self signed certificate accepted\n"); 
		#endif
	} else {
    	if(res != X509_V_OK)
			berr_exit("Certificate doesn't verify\n");
	}

    /*Check the cert chain. The chain length
      is automatically checked by OpenSSL when
      we set the verify depth in the ctx */

    /*Check the common name*/
	peer=SSL_get_peer_certificate(ssl);
	X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
      
	// WARNING NO VALIDATION Validate the hostname
	/*
	if (1) {
		printf("Peer_CN = %s\n", peer_CN);
		printf("Host = %s\n\n", host);
		//err_exit("Common name doesn't match host name");
	}
	*/
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


// Perform a connect
void doConnect (SSL *ssl, char *proto, int slices_len, int N_proxies, SPP_SLICE **slice_set, SPP_PROXY **proxies){
	// SPP CONNECT 
	if (strcmp(proto, "spp") == 0){
		#ifdef DEBUG
		printf("[DEBUG] SPP_connect\n");
		#endif 
		if (SPP_connect(ssl, slice_set, slices_len, proxies, N_proxies) <= 0){
			berr_exit("SPP connect error");
		}
	} 
	
	// SSL CONNECT 
	if (strcmp(proto, "ssl") == 0){
		#ifdef DEBUG
		printf("[DEBUG] SSL_connect\n");
		#endif
		if(SSL_connect(ssl) <= 0)
			berr_exit("SSL connect error");
   	} 
	/*
	if(require_server_auth){
	      check_cert(ssl, host);
	}
	*/
}

// Form and send GET
void sendRequest(char *filename){
		
	char request[100];
	int request_len;
	
	// Form the request 
	memset(request, 0, sizeof request);
	sprintf(request, "Get %s HTTP/1.1\r\nUser-Agent:SVA-%d\r\nHost: %s:%d\r\n\r\n", filename, clientID, host, port); 
	request_len = strlen(request);
	
	// SPP write
	if (strcmp(proto, "spp") == 0){
		#ifdef DEBUG
		printf("[DEBUG] SPP_write\n");
		#endif 
		int i; 
		for (i = 0; i < ssl->slices_len; i++){
			int r = SPP_write_record(ssl, request, request_len, ssl->slices[i]);
			check_SSL_write_error(ssl, r, request_len); 
		}
	} 
	
	// SSL write
	if (strcmp(proto, "ssl") == 0){
		#ifdef DEBUG
		printf("[DEBUG] SSL_write\n");
		#endif 
		int r = SSL_write(ssl, request, request_len);
		check_SSL_write_error(ssl, r, request_len); 
	}
}



// Read file line by line with timing information 
static void *browser_replay(void *ptr){
	char line[128];
	int previous_time = 0;      // current/previous time
	FILE *fp;                   // pointer to file

	#ifdef DEBUG
	printf("[DEBUG] Read file timing\n"); 
	#endif 

	// Retrive filename from (void *)
	char *file_name = (char *)ptr;    

	// Open file for reading
    fp = fopen(file_name,"r");  
   
    // Check for errors while opening file
    if( fp == NULL ){
        printf("Error while opening file %s.\r\n", file_name);
        return NULL; 
    }
	
    // Read file line-by-line
    while ( fgets ( line, sizeof line, fp ) != NULL ) {

		double time;
		//double duration; 
		char file_request[128]; 
	
		// Remove trailing newline (NOTE: strtoK is not thread safe)
        strtok(line, "\n");

		#ifdef DEBUG
		printf("[DEBUG] Read line is <<%s>>\n", line);
		#endif 

		// Parse line
		//sscanf(line, "%lf %lf", &time, &duration); 
		sscanf(line, "%lf %s", &time, file_request); 
		
		// Logging 
		#ifdef DEBUG
		//printf("[DEBUG] Extracted values are: %f -- %f\n", time, duration);
		printf("[DEBUG] Extracted values are: %f -- %s\n", time, file_request);
		#endif
		
		// Compute sleeping time 
		double time_to_sleep = time - previous_time; 
		#ifdef DEBUG
		printf("[DEBUG] Sleeping for %f\n", time_to_sleep); 
		#endif 
    	sleep(time_to_sleep);
		
		// Here send timed HTTP GET 
		#ifdef DEBUG
		//printf("[DEBUG] Sending GET request for file <<%s>>\n", file_request); 
		printf("[DEBUG] Sending GET request for <<%s>> bytes of data\n", file_request); 
		#endif 
		sendRequest(file_request); 
		
		// Save current time
		previous_time = time;  
	}

	#ifdef DEBUG
	printf("[DEBUG] Closing file\n"); 
	#endif 
    
	// Close file
    fclose(fp);

	// All good
	return NULL;  
}


// Emulate browser behavior based on some input traces 
static int http_complex(SSL *ssl, char *proto, char *fn){

	char buf[BUFSIZZ];
	int r, len;

	// Thread for browser-like behavior 
	pthread_t reading_thread;
	if(pthread_create(&reading_thread, NULL, browser_replay, fn)) {
		fprintf(stderr, "Error creating thread\n");
		return -1;
	}else{
		#ifdef DEBUG
		printf("[DEBUG] Reading thread started!\n"); 
		#endif
	}

	// Now read the server's response, assuming  that it's terminated by a close
	while(1){
		// SPP read
		if (strcmp(proto, "spp") == 0){
			#ifdef DEBUG
			printf("[DEBUG] Waiting on SPP_read...\n");
			#endif 
			SPP_SLICE *slice;		// slice for SPP_read
			SPP_CTX *ctx;			// context pointer for SPP_read
			r = SPP_read_record(ssl, buf, BUFSIZZ, &slice, &ctx);	
			switch(SSL_get_error(ssl, r)){
				case SSL_ERROR_NONE:
					len = r;
					break;

				case SSL_ERROR_ZERO_RETURN:
					goto shutdown;

				case SSL_ERROR_SYSCALL: 
					fprintf(stderr, "SSL Error: Premature close\n");
					goto done;

				default:
					berr_exit("SSL read problem");
			}
		} 
	
		// SSL read
		if (strcmp(proto, "ssl") == 0){
			#ifdef DEBUG
			printf("[DEBUG] Waiting on SSL_read...\n");
			#endif 
			r = SSL_read(ssl, buf, BUFSIZZ);
			switch(SSL_get_error(ssl, r)){
				case SSL_ERROR_NONE:
					len = r;
					break;

				case SSL_ERROR_ZERO_RETURN:
					goto shutdown;

				case SSL_ERROR_SYSCALL: 
					fprintf(stderr, "SSL Error: Premature close\n");
					goto done;

				default:
					berr_exit("SSL read problem");
			}
		}
		
		// Write buf to stdout
		#ifdef DEBUG
		printf("[DEBUG] Received:\n%s\n\n", buf); 
		//fwrite(buf, 1, len, stdout);
		#endif 
    }
    
	shutdown:
		r = SSL_shutdown(ssl);
		#ifdef DEBUG
		printf("[DEBUG] Shutdown was requested\n"); 
		#endif 

	switch(r){
		case 1:
			break; // Success 
		case 0:

		case -1:

		default:
			berr_exit("Shutdown failed");
	}
    
	done:
		SSL_free(ssl);
		return(0);
}

	
// Send HTTP get and wait for response (SSL/SPP)
static int http_request(SSL *ssl, char *filename, char *proto, bool requestingFile){
	
	char buf[BUFSIZZ];
	int r;
	int len; 

	// Request file (simplify with function I wrote) -- TO DO     	
	if (requestingFile){
		sendRequest(filename); 
	}

	// Now read the server's response, assuming  that it's terminated by a close
	while(1){
		// SPP read
		if (strcmp(proto, "spp") == 0){
			#ifdef DEBUG
			printf("[DEBUG] SPP_read\n");
			#endif 
			SPP_SLICE *slice;		// slice for SPP_read
			SPP_CTX *ctx;			// context pointer for SPP_read
			r = SPP_read_record(ssl, buf, BUFSIZZ, &slice, &ctx);	
			switch(SSL_get_error(ssl, r)){
				case SSL_ERROR_NONE:
					len = r;
					break;

				case SSL_ERROR_ZERO_RETURN:
					goto shutdown;

				case SSL_ERROR_SYSCALL: 
					fprintf(stderr, "SSL Error: Premature close\n");
					goto done;

				default:
					berr_exit("SSL read problem");
			}
		} 
	
		// SSL read
		if (strcmp(proto, "ssl") == 0){
			#ifdef DEBUG
			printf("[DEBUG] SSL_read\n");
			#endif 
			r = SSL_read(ssl, buf, BUFSIZZ);
			switch(SSL_get_error(ssl, r)){
				case SSL_ERROR_NONE:
					len = r;
					break;

				case SSL_ERROR_ZERO_RETURN:
					goto shutdown;

				case SSL_ERROR_SYSCALL: 
					fprintf(stderr, "SSL Error: Premature close\n");
					goto done;

				default:
					berr_exit("SSL read problem");
			}
		}
		
		// Write buf to stdout
		fwrite(buf, 1, len, stdout);
    }
    
	shutdown:
		#ifdef DEBUG
		printf("[DEBUG] Shutdown was requested\n"); 
		#endif 
		r = SSL_shutdown(ssl);

	switch(r){
		case 1:
			break; // Success 
		case 0:

		case -1:

		default:
			berr_exit("Shutdown failed");
	}
    
	done:
		SSL_free(ssl);
		return(0);
}


// Usage function 
void usage(void){
	printf("usage: wclient -s -r -w -i -f -o -a\n"); 
	printf("-s:   number of slices requested\n"); 
	printf("-r:   number of proxies with read access (per slice)\n"); 
	printf("-w:   number of proxies with write access (per slice)\n"); 
	printf("-i:   integrity check\n"); 
	printf("-c:   protocol chosen (ssl ; spp)\n"); 
	printf("-o:   {1=test handshake ; 2=200 OK ; 3=file transfer ; 4=browser-like behavior}\n");
	printf("-f:   file for http GET (needed when -o 3)\n"); 
	exit(-1);  
}


// Main function     
int main(int argc, char **argv){
	SSL_CTX *ctx;                          // SSL context
	//SSL *ssl;                              // SSL instance
	BIO *sbio;
	int sock;                              // socket descriptor 
	extern char *optarg;                   // user input parameters
	int c;                                 // user iput from getopt
	char *filename = "proxyList";          // filename for proxy
	int r = 0, w = 0;                      // slice related parameters
	char *file_requested = "index.html";   // file requeste for HTTP GET
	SPP_SLICE **slice_set;                 // slice array 
	int slices_len = 0;                    // number of slices 
	SPP_PROXY **proxies;                   // proxy array 
	int N_proxies = 0;                     // number of proxies in path 
	int action = 0;                        // specify client/server behavior (handshake, 200OK, serve file, browser-like)
	char *file_action = NULL;              // file action to use for browser-liek behavior
	
	// Handle user input parameters
	while((c = getopt(argc, argv, "s:r:w:i:f:c:o:a:")) != -1){
			
			switch(c){
	
			// Number of slices
			case 's':
				if(! (slices_len = atoi(optarg) ))
					err_exit("Bogus number of slices specified (no. of slices need to be > 0)");
				break;
		
			// Number of proxies with read access (per slice)
			case 'r':
				r = atoi(optarg); 
				break;

			// Number of proxies with write access (per slice)
			case 'w':
				w = atoi(optarg); 
				break;

        	// Integrity check requested 
			case 'i':
				require_server_auth = 0;
				break; 
      		
			// Protocol chosen
			case 'c':
				if(! (proto = strdup(optarg) ))
					err_exit("Out of memory");
				break; 
			
			// File requested for HTTP GET
			case 'f':
				if(! (file_requested = strdup(optarg) ))
					err_exit("Out of memory");
				break; 

			// Client/Server behavior 
			case 'o':
				action = atoi(optarg); 
				break; 

			// Action file 
			// NOTE: necessary only if  -o 4, i.e., browser-like behavior
			case 'a':
				if(! (file_action = strdup(optarg) ))
					err_exit("Out of memory");
				break; 
			
			// default case 
			default:
				usage(); 
				break; 
		}
    }


	// Read number of proxy from file 
	N_proxies = read_proxy_count(filename); 
	
	// Check that input parameters are correct 
	#ifdef DEBUG
	printf("[DEBUG] Parameters count: %d\n", argc); 
	#endif
	if (argc == 1){
		usage(); 
	}
	if (action < 1 || action > 4){
		usage(); 
	}
	if ((strcmp(proto, "spp") != 0) && (strcmp(proto, "ssl") != 0)){
		printf("Protocol type specified is not supported. Supported protocols are: spp, ssl\n"); 
		usage(); 
	}
	if (N_proxies == 0){
		printf ("At least one proxy needs to be defined, i.e., the final server\n"); 
		usage(); 
	}
	if (r > N_proxies || w > N_proxies){
		printf ("The values for r and w need to be <= than the number of proxies\n"); 
		usage(); 
	}
	if(action == 4){
		if (file_action == NULL){
			printf ("Action file (-a path_to_file) is required with -o 4\n"); 
			usage(); 
		}
	}

	// Generate a clientID
	time_t t;
	srand((unsigned) time(&t));
	clientID = rand() % MAX_CONC_CLIENT; 

	// Construct string for client/server behavior
	char *temp_str = "undefined";
	if (action == 1)
		temp_str = "handshake_only";  
	if (action == 2)
		temp_str = "200_OK";  
	if (action == 3)
		temp_str = "serve_file";	
	if (action == 4)
		temp_str = "browser_like";	

	// Logging input parameters 
	#ifdef DEBUG
	printf("[DEBUG] CLIENT-ID=%d host=%s port=%d slices=%d read=%d write=%d n_proxies=%d proto=%s action=%d(%s)\n", clientID, host, port, slices_len, r, w, N_proxies, proto, action, temp_str); 
	#endif 

	// Build SSL context
	ctx = initialize_ctx(KEYFILE, PASSWORD, proto);
	ssl = SSL_new(ctx);

	// Allocate memory for proxies 	
	proxies  = malloc( N_proxies * sizeof (SPP_PROXY*));

	// Read proxy list 
	read_proxy_list(filename, proxies, ssl);

	// Print proxy list 
	#ifdef DEBUG
	print_proxy_list(proxies, N_proxies); 
	#endif

	// Connect TCP socket
	char* address = (char*)malloc(strlen(proxies[0]->address)+1); // Large enough for string+\0
	memcpy(address, proxies[0]->address, strlen(proxies[0]->address)+1);
	char* proxy_host = strtok(address, ":"); 
	int proxy_port = atoi(strtok(NULL, ":"));
	#ifdef DEBUG 
	printf("[DEBUG] Opening socket to host: %s, port %d\n", proxy_host, proxy_port);
	#endif
	sock = tcp_connect(proxy_host, proxy_port);
	
	/*
	// Connect TCP socket
	if (N_proxies > 0){
		char* address = (char*)malloc(strlen(proxies[0]->address)+1); // Large enough for string+\0
		memcpy(address, proxies[0]->address, strlen(proxies[0]->address)+1);
		char* proxy_host = strtok(address, ":"); 
		int proxy_port = atoi(strtok(NULL, ":"));
		#ifdef DEBUG 
		printf("[DEBUG] Opening socket to host: %s, port %d\n", proxy_host, proxy_port);
		#endif
		sock = tcp_connect(proxy_host, proxy_port);
	}else{
		#ifdef DEBUG 
		printf("[DEBUG] Opening socket to host: %s, port %d\n", host, port);
		#endif
		sock = tcp_connect(host, port);
	}
	*/

	// Connect the SSL socket 
	sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);

	// Create slices_n slices with incremental purpose 
	int i; 
	//SPP_SLICE *slice_set[slices_len];
	slice_set  = malloc( slices_len * sizeof (SPP_SLICE*));
	#ifdef DEBUG
	printf("[DEBUG] Generating %d slices\n", slices_len); 
	#endif
	for (i = 0;  i < slices_len; i++){
		char *newPurpose;  
		char str[30]; 
		sprintf (str, "slices_%d", i); 
		newPurpose = (char *)malloc(strlen(str));    
		strcpy(newPurpose, str);
		slice_set[i] = SPP_generate_slice(ssl, newPurpose); 
		#ifdef DEBUG
		printf("\t[DEBUG] Generated slices %d with purpose %s\n", slice_set[i]->slice_id, slice_set[i]->purpose); 
		#endif
	}

	// Assign write access to proxies for all slices 
	// Find MAX between r and w
	int MAX = r; 
	if (w > r) 
		MAX = w; 
		
	// Iterate among proxies
	for (i = 0; i < MAX ; i++){
		// assign read access if requested
		if (i < r){
			if (SPP_assign_proxy_read_slices(ssl, proxies[i], slice_set, slices_len) == 1 ) {
				#ifdef DEBUG
				printf ("[DEBUG] Proxy %s assigned read access to slice-set (READ_COUNT=%d)\n", proxies[i]->address, (i + 1)); 
				#endif
			}
		}

		// assign write access if requested
		if (i < w){
			if (SPP_assign_proxy_write_slices(ssl, proxies[i], slice_set, slices_len) == 1 ) {
				#ifdef DEBUG
				printf ("Proxy %s correctly assigned write access to slice-set (WRITE COUNT=%d)\n", proxies[i]->address, (i + 1)); 
				#endif
			}
		}
	}
	
	// Let's connect
	doConnect (ssl, proto, slices_len, N_proxies, slice_set, proxies); 
	
	// Switch across possible client-server behavior
	// // NOTE: here we can add more complex strategies
	switch(action){
		// Handshake only 
		case 1:  
			break; 
                
		// Send simple request, wait for 200 OK
		case 2:  
			http_request(ssl, file_requested, proto, false);
			break; 

		// Send HTTP GET request and wait for file to be received
		case 3:  		
			http_request(ssl, file_requested, proto, true);
			break; 

		// Send several GET request following a browser-like behavior  
		case 4:  
			http_complex(ssl, proto, file_action);
			break; 
 
		// Unknown option 
		default: 
			usage();
			break; 
	}


	// Remove SSL context
    destroy_ctx(ctx);
    
	// Clode socket
    close(sock);

	//Free memory 
	for (i = 0; i < N_proxies ; i++){
	    free(proxies[i]);
	}
	for (i = 0; i < slices_len; i++){
		free(slice_set[i]); 
	}
	
	// All good
	return 0; 
}
