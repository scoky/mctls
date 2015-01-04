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

#include <stdbool.h>			// to support boolean
#include "common.h"				// common library between client and server
#define KEYFILE "client.pem"	// client certificate
#define PASSWORD "password"		// unused now 	
#define DEBUG					// verbose logging
//#define PROXY					// at least one proxy is physically available
#define CONNECT_TIMEOUT 5		// socket connection timeout 


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
	printf("Expected number of proxies is: %d\r\n", N);
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
		#ifdef DEBUG
		printf("Value read is: %s\r\n", line);
		#endif 
		
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
		#ifdef DEBUG
		printf("Proxy %d stored has address: %s\r\n", count, proxies[count]->address);
		count++; 
		int j; 
		for (j = 0; j < count; j++){
			printf("Previous proxy was %s\r\n",  proxies[j]->address);
		#endif
		}
	}
	
	// Close file
	fclose(fp);
}

// Function to read a proxy list from file and populate array of proxies
void print_proxy_list(SPP_PROXY **proxies, int N){
	int i; 
	
	#ifdef DEBUG	
	printf("Print proxy list. There are %d available proxies.\r\n", N);	
	#endif 
	for (i = 0; i < N; i++){
		printf("Proxy %d -- %s\r\n", i, proxies[i]->address);
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
	X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
      
	// WARNING NO VALIDATION Validate the hostname
	if (1) {
		printf("Peer_CN = %s\n", peer_CN);
		printf("Host = %s\n\n", host);
		//err_exit("Common name doesn't match host name");
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


//HTTP REQUEST -- TO DO (check size calculation since I am sending more junk that I should)
//static char *REQUEST_TEMPLATE = "GET / HTTP/1.0\r\nUser-Agent:" "SVAClient\r\nHost: %s:%d\r\n\r\n";
//static char *REQUEST_TEMPLATE = "GET %s HTTP/1.0\r\nUser-Agent:" "SVAClient\r\nHost: %s:%d\r\n\r\n";
static char *REQUEST_TEMPLATE = "GET %s HTTP/1.0\r\n"
								"User-Agent:SVAClient\r\n"
     							"Content-type: application/x-www-form-urlencoded\r\n"
     							"Content-length: %d\r\n"
								"Host: %s:%d\r\n\r\n";
static char *host=HOST;
static int port=PORT;
static int require_server_auth=1;

// Make an HTTP request  -- add filename here 
static int http_request(SSL *ssl, char *filename, char *proto){
	char *request=0;
	char buf[BUFSIZZ];
	int r;
	int len, request_len;
    	
	// Construct HTTP request 
	request_len = strlen(REQUEST_TEMPLATE) + strlen(host) + strlen(filename) + 6;
	if(!(request = (char *)malloc(request_len))){
		err_exit("Couldn't allocate request");
	}

	// Write request_len bytes to request by replacing input into the template 
	snprintf(request, request_len, REQUEST_TEMPLATE, filename, request_len, host, port);

	// Find exact request_len
	request_len = strlen(request);

	// SPP write
	if (strcmp(proto, "spp") == 0){
		#ifdef DEBUG
		printf("[DEBUG] SPP_write\n");
		#endif 
		int i; 
		for (i = 0; i < ssl->slices_len; i++){
			r = SPP_write_record(ssl, request, request_len, ssl->slices[i]);
			check_SSL_write_error(ssl, r, request_len); 
		}
	} 
	
	// SSL write
	if (strcmp(proto, "ssl") == 0){
		#ifdef DEBUG
		printf("[DEBUG] SSL_write\n");
		#endif 
		r = SSL_write(ssl, request, request_len);
		check_SSL_write_error(ssl, r, request_len); 
	}

	// Now read the server's response, assuming  that it's terminated by a close
	while(1){
		// SPP read
		if (strcmp(proto, "spp") == 0){
			#ifdef DEBUG
			printf("[DEBUG] SPP_read\n");
			#endif 
			// ssl->spp_read_ctx???? 
			r = SPP_read_record(ssl, buf, BUFSIZZ, ssl->slices, &ssl->spp_read_ctx);	
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
		free(request);
		return(0);
}


// Usage function 
void usage(void){
	printf("usage: wclient -h -p -s -r -w -i -f\n"); 
	printf("[default host=localhost ; default port=4433]"); 
	printf("-h:   name of host to connect to\n"); 
	printf("-p:   port of host to connect to\n"); 
	printf("-s:   number of slices requested\n"); 
	printf("-r:   number of proxies with read access (per slice)\n"); 
	printf("-w:   number of proxies with write access (per slice)\n"); 
	printf("-i:   integrity check\n"); 
	printf("-f:   file for http GET\n"); 
	printf("-c:   protocol chosen (sll ; spp)\n"); 
	exit(-1);  
}


// Main function     
int main(int argc, char **argv){
	SSL_CTX *ctx;							// SSL context
	SSL *ssl;								// SSL context
	BIO *sbio;								// ?
	int sock;								// socket
	extern char *optarg;					// user input parameters
	int c;									// user iput from getopt
	int N_proxies = 0;						// number of proxies indicated
	char *filename = "proxyList"; 			// filename for proxy
	int slices_len = 0, r = 0, w = 0;		// slice related parameters
	char *file_requested = "index.html";	// file requeste for HTTP GET
	char *proto = "ssl"; 					// protocl of choice 

	// Handle user input parameters
	while((c = getopt(argc, argv, "h:p:s:r:w:i:f:c:")) != -1){
			
			switch(c){
	
			// Hostname
			case 'h':
				if(! (host = strdup(optarg) ))
					err_exit("Out of memory");
				break; 

        	// Port
			case 'p':
				if(! (port = atoi(optarg) ))
					err_exit("Bogus port specified");
				break;
		
			// Number of slices
			case 's':
				if(! (slices_len = atoi(optarg) ))
					err_exit("Bogus number of slices specified");
				break;
		
			// Number of proxies with read access (per slice)
			case 'r':
				if(! (r = atoi(optarg) ))
					err_exit("Bogus number of read access specified");
				break;

			// Number of proxies with write access (per slice)
			case 'w':
				if(! (w = atoi(optarg) ))
					err_exit("Bogus number of write access specified");
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
					
			// default case 
			default:
				usage(); 
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
	
	if ((strcmp(proto, "spp") != 0) && (strcmp(proto, "ssl") != 0)){
		printf("Protocol type specified is not supported. Support proto are: spp, ssl\n"); 
		usage(); 
	}

	// Read number of proxy from file 
	N_proxies = read_proxy_count(filename); 
	printf("INPUT host=%s port=%d slices=%d read=%d write=%d n_proxies=%d proto=%s\n", host, port, slices_len, r, w, N_proxies, proto); 
	if (r > N_proxies || w > N_proxies){
		printf ("Check your values for r and w\n"); 
		usage(); 
	}

	// Allocate memory for proxies 	
	SPP_PROXY *proxies[N_proxies]; 
	
    // Build SSL context
	ctx = initialize_ctx(KEYFILE, PASSWORD, proto);
	ssl = SSL_new(ctx);

	// Read proxy list 
	read_proxy_list(filename, proxies, ssl);

	// Print proxy list 
	#ifdef DEBUG
	print_proxy_list(proxies, N_proxies); 
	#endif

	// Connect TCP socket
	#ifdef PROXY
	// Following line can be an issue when we want common name to match hostname and a proxy is used 
	// host = proxies[0]->address; 
	#ifdef DEBUG 
	printf("Opening socket to host: %s, port %d\n", proxies[0]->address, port);
	#endif
	sock = tcp_connect(proxies[0]->address, port);
	#else
	#ifdef DEBUG 
	printf("Opening socket to host: %s, port %d\n", host, port);
	#endif
	sock = tcp_connect(host, port);
	#endif
	
	// Connect the SSL socket 
	sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);

	// Create slices_n slices with incremental purpose 
	int i; 
	SPP_SLICE *slice_set[slices_len];
	#ifdef DEBUG
	printf("Generating %d slices\n", slices_len); 
	#endif
	for (i = 0;  i < slices_len; i++){
		char *newPurpose;  
		char str[30]; 
		sprintf (str, "slices_%d", i); 
		newPurpose = (char *)malloc(strlen(str));    
		strcpy(newPurpose, str);
		slice_set[i] = SPP_generate_slice(ssl, newPurpose); 
		#ifdef DEBUG
		printf("Generated slices %d with purpose %s\n", slice_set[i]->slice_id, slice_set[i]->purpose); 
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
				printf ("Proxy %s correctly assigned read access to slice-set (READ_COUNT=%d)\n", proxies[i]->address, (i + 1)); 
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

	// SPP CONNECT 
	if (strcmp(proto, "spp") == 0){
		#ifdef DEBUG
		printf("SPP_connect\n");
		#endif 
		if (SPP_connect(ssl, slice_set, slices_len, proxies, N_proxies) <= 0){
			berr_exit("SPP connect error");
		}
	} 
	
	// SSL CONNECT 
	if (strcmp(proto, "ssl") == 0){
		#ifdef DEBUG
		printf("SSL_connect\n");
		#endif
		if(SSL_connect(ssl) <= 0)
			berr_exit("SSL connect error");
    
		if(require_server_auth){
	      check_cert(ssl, host);
		}
 
	    // Make HTTP request -- TO DO:  extend by passing filename!
	    http_request(ssl, file_requested, proto);
	}

    // Shutdown the socket
    destroy_ctx(ctx);
    close(sock);

	//Free memory 
	for (i = 0; i < N_proxies ; i++){
	    free(proxies[i]);
	}
	for (i = 0; i < slices_len; i++){
		free(slice_set[i]); 
	}
	
	// All done
    exit(0);
  }

