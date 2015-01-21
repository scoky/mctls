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
//#define DEBUG                 // verbose logging
#define CONNECT_TIMEOUT 5       // socket connection timeout 
#define MAX_CONC_CLIENT 100     // max concurrent clients

static char *host=HOST;
static int port=PORT;
static int require_server_auth = 1;
static int clientID=0; 

// -- Moved up here just because of thread 
static SSL *ssl;                              // SSL instance
static int plain_socket;
static char *proto = "ssl";                   // protocol to use (ssl ; spp)  
static int stats=0;                           // Report byte statistics boolean
static int sizeCheck; 

void print_stats(SSL *s);


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
void read_proxy_list(char *file_name, SPP_PROXY **proxies){
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
void check_cert(char *host){
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
void check_SSL_write_error(int r, int request_len){
	
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
void doConnect (char *proto, int slices_len, int N_proxies, SPP_SLICE **slice_set, SPP_PROXY **proxies){
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

	// TO DO -- Check here 	
	if(require_server_auth){
		#ifdef DEBUG
		printf("[DEBUG] Check certificate\n");
		#endif
		check_cert(host);
	}
}

// Form and send GET
void sendRequest(char *filename){
		
	char request[100];
	int request_len;
	
	// Form the request 
	memset(request, '0', sizeof(request));
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
			#ifdef DEBUG
			printf("[DEBUG] Wrote %d bytes\n", r);
			#endif
			check_SSL_write_error(r, request_len); 
		}
	} 
	// SSL write
	else if (strcmp(proto, "ssl") == 0){
		#ifdef DEBUG
		printf("[DEBUG] SSL_write\n");
		#endif 
		int r = SSL_write(ssl, request, request_len);
		check_SSL_write_error(r, request_len); 
	}
	// socket write
	else if (strcmp(proto, "pln") == 0){
		#ifdef DEBUG
		printf("[DEBUG] Plain socket write\n");
		#endif 
	    int r = write(plain_socket, request, request_len);
	    if ( r <= 0 )
	    {
	    	printf("Something went wrong with writing to the socket!\n");
	    }
		
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
static int http_complex(char *proto, char *fn){

	int r; 
	char buf[BUFSIZZ];

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
			#ifdef DEBUG
			printf("Read %d bytes\n", r);
			#endif
			
			switch(SSL_get_error(ssl, r)){
				case SSL_ERROR_NONE:
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
		else if (strcmp(proto, "ssl") == 0){
			#ifdef DEBUG
			printf("[DEBUG] Waiting on SSL_read...\n");
			#endif 
			r = SSL_read(ssl, buf, BUFSIZZ);
			switch(SSL_get_error(ssl, r)){
				case SSL_ERROR_NONE:
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
		else if (strcmp(proto, "pln") == 0){
			r = read(plain_socket, buf, BUFSIZZ);
			#ifdef DEBUG 
			printf("[DEBUG] Read %d bytes\n", r);
			#endif
			if ( r <= 0 ) /* done reading */
				goto done;
		}
		
		// Write buf to stdout
		#ifdef DEBUG
		printf("[DEBUG] Received:\n%s\n\n", buf); 
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
				#ifdef DEBUG 
				printf ("Shutdown failed with code %d\n", r);
				#endif 
				berr_exit("Shutdown failed"); 
		}
    
	done:
		//  Print byte statistics
		if (stats){
			print_stats(ssl);        
		}
		// Free ssl 
		SSL_free(ssl);
		
		// All good 
		return(0);
}

// Send HTTP get and wait for response (SSL/SPP)
static int http_request(char *filename, char *proto, bool requestingFile, struct timeval *tvEnd){
	
	char buf[BUFSIZZ];
	int r;
	int len; 
	bool flag = false; 

    // Compute expected data size
	int fSize = atoi(filename);
    if (fSize == 0 && filename[0] != '0'){
		if (requestingFile){
			fSize = calculate_file_size(filename);
		}else{
	    	fSize = strlen("HTTP/1.0 200 OK\r\n"); 
		}
	}   
	sizeCheck = fSize; 

	// Request file (either by name or by size) 
	if (requestingFile){
		sendRequest(filename); 
	}

	// Now read the server's response, assuming  that it's terminated by a close
	while(1){
		// SPP read
		if (strcmp(proto, "spp") == 0){
			/*
			#ifdef DEBUG
			printf("[DEBUG] SPP_read\n");
			#endif 
			*/
			SPP_SLICE *slice;		// slice for SPP_read
			SPP_CTX *ctx;			// context pointer for SPP_read
			r = SPP_read_record(ssl, buf, BUFSIZZ, &slice, &ctx);	
			#ifdef DEBUG 
			printf("[INFO] Read %d bytes\n", r);
			#endif
			if ((ssl->read_stats.app_bytes == fSize) && (! flag)){
				printf("[INFO] Read %d bytes as expected (fSize=%d). Stopping timer\n", ssl->read_stats.app_bytes, fSize);
				// Stop the timer here (avoid shutdown crap) 
				gettimeofday(tvEnd, NULL);
				flag = true; 
				goto shutdown;
			}
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
		else if (strcmp(proto, "ssl") == 0){
			/*
			#ifdef DEBUG
			printf("[DEBUG] SSL_read\n");
			#endif 	
			*/
			r = SSL_read(ssl, buf, BUFSIZZ);
			#ifdef DEBUG 
			printf("[DEBUG] Read %d bytes\n", r);
			#endif
			if ((ssl->read_stats.app_bytes == fSize) && (! flag)){
				printf("[INFO] Read %d bytes as expected (fSize=%d). Stopping timer\n", ssl->read_stats.app_bytes, fSize);
				// Stop the timer here (avoid shutdown crap) 
				gettimeofday(tvEnd, NULL);
				flag = true; 
			}
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
		else if (strcmp(proto, "pln") == 0){
			r = read(plain_socket, buf, BUFSIZZ);
			#ifdef DEBUG 
			printf("[DEBUG] Read %d bytes\n", r);
			#endif
			if ( r <= 0 ) /* done reading */
				goto done;
		}
		
		// Write buf to stdout
		#ifdef VERBOSE
		fwrite(buf, 1, len, stdout);
		#endif 
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
				#ifdef DEBUG 
				printf ("Shutdown failed with code %d\n", r);
				#endif 
				berr_exit("Shutdown failed"); 
	}
    
	done:
		if (stats){
			print_stats(ssl);
		}
		SSL_free(ssl);
		return(0);
}


// report "BYTE STATISITICS"
void print_stats(SSL *s) {
    printf("[RESULTS] BYTE STATISITICS:\n");
    printf("[RESULTS] Bytes read: %d\n", s->read_stats.bytes);
    printf("[RESULTS] Application bytes read: %d [Expected %d]\n", s->read_stats.app_bytes, sizeCheck); 
    printf("[RESULTS] Block padding bytes read: %d\n", s->read_stats.pad_bytes);
    printf("[RESULTS] Header bytes read: %d\n", s->read_stats.header_bytes);
    printf("[RESULTS] Handshake bytes read: %d\n", s->read_stats.handshake_bytes);
    printf("[RESULTS] Bytes write: %d\n", s->write_stats.bytes);
    printf("[RESULTS] Application bytes write: %d\n", s->write_stats.app_bytes);
    printf("[RESULTS] Block padding bytes write: %d\n", s->write_stats.pad_bytes);
    printf("[RESULTS] Header bytes write: %d\n", s->write_stats.header_bytes);
    printf("[RESULTS] Handshake bytes write: %d\n", s->write_stats.handshake_bytes);
}


// Usage function 
void usage(void){
	printf("usage: wclient -s -r -w -i -f -o -a -c -b\n"); 
	printf("-s:   number of slices requested (min 2, 1 for handshake 1 for rest)\n"); 
	printf("-r:   number of proxies with read access (per slice)\n"); 
	printf("-w:   number of proxies with write access (per slice)\n"); 
	printf("-i:   integrity check\n"); 
	printf("-f:   file for http GET (either via <name> (require file to exhist both at server and client[for testing reasons]) or via <size>)\n"); 
	printf("-o:   {1=test handshake ; 2=200 OK ; 3=file transfer ; 4=browser-like behavior}\n");
	printf("-a:   action file for browser-like behavior\n");
	printf("-c:   protocol chosen (ssl ; spp; pln)\n"); 
	printf("-b:   report byte statistics\n");
	exit(-1);  
}


/* Compute a time difference - NOTE: Return 1 if the difference is negative, otherwise 0 [now defined in the library]
int timeval_subtract(struct timeval *result, struct timeval *t2, struct timeval *t1)
{
    long int diff = (t2->tv_usec + 1000000 * t2->tv_sec) - (t1->tv_usec + 1000000 * t1->tv_sec);
    result->tv_sec = diff / 1000000;
    result->tv_usec = diff % 1000000;

    return (diff<0);
}
*/

// Main function     
int main(int argc, char **argv){
	SSL_CTX *ctx;                          // SSL context
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
	struct timeval tvBeginConnect; 
	struct timeval tvEndConnect; 
	struct timeval tvBegin, tvEnd; 
	struct timeval tvConnect, tvDuration;  // time structures for handshake duration 

	
	// Handle user input parameters
	while((c = getopt(argc, argv, "s:r:w:i:f:c:o:a:b:")) != -1){
			
			switch(c){
	
			// Number of slices
			case 's':	if(! (slices_len = atoi(optarg) )){
							err_exit("Bogus number of slices specified (no. of slices need to be > 1)");
						}
						break;
		
			// Number of proxies with read access (per slice)
			case 'r':	r = atoi(optarg); 
						break; 

			// Number of proxies with write access (per slice)
			case 'w':	w = atoi(optarg); 
						break; 

        	// Integrity check requested 
			case 'i':	require_server_auth = 0;
						break; 
      		
			// Protocol chosen
			case 'c':	if(! (proto = strdup(optarg) )){
							err_exit("Out of memory");
						}
						if (strcmp(proto, "fwd") == 0){
                  			proto = "ssl"; 
						}
						if (strcmp(proto, "spp_mod") == 0){
                  			proto = "spp"; 
						}
						break; 
			
			// File requested for HTTP GET
			case 'f':	if(! (file_requested = strdup(optarg) )){
							err_exit("Out of memory");
						}
						break; 

			// Client/Server behavior 
			case 'o':	action = atoi(optarg); 
						break; 

			// Action file 
			// NOTE: necessary only if  -o 4, i.e., browser-like behavior
			case 'a':	if(! (file_action = strdup(optarg) )){
							err_exit("Out of memory");
						}
						break; 
                                
			// Print byte statistics 
			case 'b':	stats = atoi(optarg);
						break; 

			// default case 
			default:	usage(); 
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
	if ((strcmp(proto, "spp") == 0) && slices_len < 1){
		printf("No. of slices need to be > 0"); 
		usage(); 
	}
	if (action < 1 || action > 4){
		usage(); 
	}
	if ((strcmp(proto, "spp") != 0) && (strcmp(proto, "ssl") != 0) && (strcmp(proto, "pln") != 0)){
		printf("Protocol type specified is not supported. Supported protocols are: spp, ssl, pln\n"); 
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
	char *temp_str; 
	if (action == 1){
		temp_str = "handshake_only";  
	}
	if (action == 2){
		temp_str = "200_OK";  
	}
	if (action == 3){
		temp_str = "serve_file";	
	}
	if (action == 4){
		temp_str = "browser_like";	
	}

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
	read_proxy_list(filename, proxies);

	// Print proxy list 
	#ifdef DEBUG
	print_proxy_list(proxies, N_proxies); 
	#endif

	// Create slices_n slices with incremental purpose 
	gettimeofday(&tvBegin, NULL);
	int i; 
	//SPP_SLICE *slice_set[slices_len];
	slice_set  = malloc( slices_len * sizeof (SPP_SLICE*));
	#ifdef DEBUG
	printf("[DEBUG] Generating %d slices\n", slices_len); 
	#endif
	for (i = 0;  i < slices_len; i++){
		char *newPurpose;  
		char str[30]; 
		sprintf (str, "slices_%d", (i + 2)); 
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
	// TCP Connect
	char* address = (char*)malloc(strlen(proxies[0]->address)+1); // Large enough for string+\0
	memcpy(address, proxies[0]->address, strlen(proxies[0]->address)+1);
	host = strtok(address, ":");
	port = atoi(strtok(NULL, ":")); 
	#ifdef DEBUG 
	printf("[DEBUG] Opening socket to host: %s, port %d\n", host, port);
	#endif
	sock = tcp_connect(host, port);
	plain_socket = sock;
	// Connect TCP socket to SSL socket 

	// don't init ssl for unencrypted data...
	if (strcmp(proto, "pln") != 0) 
	{
		sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    	SSL_set_bio(ssl, sbio, sbio);
    
		// SSL Connect 
		gettimeofday(&tvBeginConnect, NULL);
		doConnect (proto, slices_len, N_proxies, slice_set, proxies); 
		gettimeofday(&tvEndConnect, NULL);
		timeval_subtract(&tvConnect, &tvEndConnect, &tvBeginConnect);
	}

	// Switch across possible client-server behavior
	// // NOTE: here we can add more complex strategies
	switch(action){
		// Handshake only 
		case 1:  
			break; 
                
		// Send simple request, wait for 200 OK
		case 2:  
			http_request(file_requested, proto, false, &tvEnd);
			break; 

		// Send HTTP GET request and wait for file to be received
		case 3:  		
			http_request(file_requested, proto, true, &tvEnd);
			break; 

		// Send several GET request following a browser-like behavior  
		case 4:  
			http_complex(proto, file_action);
			gettimeofday(&tvEnd, NULL);
			break; 
 
		// Unknown option 
		default: 
			usage();
			break; 
	}
	// Compute duration of action
	if (action > 1){
		timeval_subtract(&tvDuration, &tvEnd, &tvBeginConnect);
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

	// Report time statistics
	if (action > 1){
		printf("[RESULTS] No_Slices %d Action %s_%d Duration %ld.%06ld\n", slices_len, temp_str, sizeCheck, tvDuration.tv_sec, tvDuration.tv_usec);	
	}else{
		printf("[RESULTS] No_Slices %d Action %s Handshake_Dur %ld.%06ld\n", slices_len, temp_str, tvConnect.tv_sec, tvConnect.tv_usec);	
	}
	
	// All good
	return 0; 
}
