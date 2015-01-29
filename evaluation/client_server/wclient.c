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
static ExperimentInfo *experiment_info;       // for printing stats at the end
static int lines = 0;                         // number of lines in action file
static long fSize = 0; 

//nagle stuff
static int disable_nagle = 0;

// allow acces to number of slices also for SSL 
static int slices_len = 0;                    // number of slices 

// Thread syncronization variables 
static int done = 0;
static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t c = PTHREAD_COND_INITIALIZER;
static bool running = true; 

// Thread sync functions 
pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m);
pthread_cond_signal(pthread_cond_t *c);

// thread exit 
void thr_exit() {
	pthread_mutex_lock(&m);
	done = 1;
	pthread_cond_signal(&c);
	pthread_mutex_unlock(&m);
}

// Join 
void thr_join() {
	pthread_mutex_lock(&m);
	while (done == 0){
		pthread_cond_wait(&c, &m);
	}
	pthread_mutex_unlock(&m);
}


// function to plot statistics
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
	N = atoi(line); 
	
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
		newLine = (char *)malloc(strlen(line)+1);    
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

    if (disable_nagle == 1)
    	set_nagle(sock, 1); 


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

// string tokenizer 
int TokenizeString(char *s_String, char s_Token[][25], char c_Delimiter){
	int j = 0;
	unsigned int i_Offset = 0;
	char b_Flag = 0;
	int count = 0;
	#ifdef DEBUG
	//printf("[DEBUG] TokenizeString %d - %d\n", i_Offset, strlen(s_String)); 
	#endif
	for (i_Offset = 0;i_Offset <= strlen(s_String);i_Offset++){
		#ifdef DEBUG
		//printf("[DEBUG] Indices %d - %d\n", i_Offset, strlen(s_String)); 
		#endif
		if (s_String[i_Offset] != c_Delimiter && s_String[i_Offset] != '\t' && s_String[i_Offset] != '\n' && s_String[i_Offset] != '\0'){
			s_Token[count][j] = s_String[i_Offset];
			j++;
			b_Flag = 1;
			continue;
		}
		if (b_Flag){
		s_Token[count][j] = '\0';
		count++;
		j = 0;
		b_Flag = 0;
		}
	}
	return (count - 1);
}

// Form and send GET
void sendRequestBrowser(char *filename){

	
	#ifdef DEBUG
	printf("[DEBUG] Inside sendRequestBrowser\n"); 
	#endif 	
	
	int r; 
	
	int req_len_arr[slices_len]; 
	int request_len = 0; 
	
	// Remove trailing newline (NOTE: strtoK is not thread safe)
	//strtok(filename, "\n");

	// extract list of response sizes 
	char *str = strtok(filename, ";");
	#ifdef DEBUG
	printf("[DEBUG] Extracted string is %s with length %d\n", str, strlen(str)); 
	#endif 	
	str = strtok(NULL, ";"); 
	char *resp_sizes = strtok(str, " "); 
	#ifdef DEBUG
	printf("[DEBUG] Extracted string is %s with length %d\n", resp_sizes, strlen(resp_sizes)); 
	#endif 	
 
	// extract request sizes 
	char s_Token[slices_len][25];
	//memset(s_Token, 0, 200);
	memset(s_Token, 0, sizeof(s_Token));
	int count = TokenizeString(filename, s_Token, '_');
	int ii;
	for(ii=0; ii <= count; ii++){
		req_len_arr[ii] = atoi(s_Token[ii]); 
		#ifdef VERBOSE
		printf("[VERBOSE] Tokenized string is %s - Value %d [%d-%d]\n", s_Token[ii], req_len_arr[ii], ii, count); 
		#endif VERBOSE
		request_len += req_len_arr[ii]; 
	}
	// compute total response size
	memset(s_Token, 0, 200);
	fSize = 0; 
	count = TokenizeString(resp_sizes, s_Token, '_');
	int i;
	for(i=0; i <= count; i++){
		fSize += atol(s_Token[i]); 
	}
 
	#ifdef DEBUG
	printf("[DEBUG] String %s with lenght %d\n", resp_sizes, strlen(resp_sizes)); 
	printf("[DEBUG] Expected response with size %d\n", fSize); 
	#endif 	
	
	// prepare common GET request
	char get_str[200];
	memset(get_str, '0', sizeof(get_str));
	int get_len;
	sprintf(get_str, "Get %s HTTP/1.1\r\nUser-Agent:SVA-%d\r\nHost: %s:%d\nPadding:", resp_sizes, clientID, host, port); 
	get_len = strlen(get_str); 
	#ifdef DEBUG
	printf ("[DEBUG] GET string (size %d):\n%s\n", get_len, get_str); 
	#endif 	
	
	//prepare final request with appropriate padding
	char *request;
	int actual_request_len;
	char *padding=NULL;
	
	int toAllocate; 
	if (strcmp(proto, "spp") == 0){
		toAllocate = (req_len_arr[0] - get_len); 
	} else {
		toAllocate = (request_len - get_len); 
	}
        if (toAllocate < 0) {
		toAllocate = 0;
	}

	// Deal with the case when the GET is bigger than requested slice 0 
	if (toAllocate < 0){
		toAllocate = 0;
	}

	// Logging
	#ifdef DEBUG	
	printf ("[DEBUG] Allocating %d for padding\n", toAllocate + 1); 
	#endif 
	padding = (char*) malloc(toAllocate + 1);
	memset(padding, '?', toAllocate);
	padding[toAllocate] = 0;
	if (strcmp(proto, "spp") == 0){
		actual_request_len = (req_len_arr[0] > strlen(get_str) ? req_len_arr[0] : strlen(get_str)) + 1;
	}else{
		actual_request_len = (request_len > strlen(get_str) ? request_len : strlen(get_str)) + 1;
	}
	request = (char *)malloc(actual_request_len);
	// Copy get_str without \0
	memcpy(request, get_str, strlen(get_str));
	// Copy padding with \0
	memcpy(request+strlen(get_str), padding, strlen(padding)+1);

	//sprintf(request, "%s %s\r\n\r\n", get_str, padding); 
	//sprintf(request, "%s%s", get_str, padding); 
	
	
	#ifdef DEBUG
	printf ("[DEBUG] Padded GET request (size %d):\n", strlen(request)); 
	#endif 	
	#ifdef VERBOSE
	printf ("[DEBUG] Content:\n%s\n", request); 
	#endif
	// SPP write
	if (strcmp(proto, "spp") == 0){
		#ifdef DEBUG
		printf("[DEBUG] SPP_write\n");
		#endif 
		int i;  
		for (i = 0; i < ssl->slices_len; i++){
			if (i == 0){
				#ifdef DEBUG
				printf ("[DEBUG] Send GET request with slice %d. Actual size %d  -- size requested %d.\n", i, strlen(request), req_len_arr[i]); 
				#endif 	
				r = SPP_write_record(ssl, request, strlen(request)+1, ssl->slices[i]); // req_len_arr[i]
				//r = SPP_write_record(ssl, request, strlen(request), ssl->slices[i]);
				#ifdef DEBUG
				printf ("[DEBUG] Send GET request with slice %d. Actual size %d  -- size requested %d. SPP_write returned %d\n", i, strlen(request), req_len_arr[i], r); 
				#endif 	
				// Check for errors 	
				//check_SSL_write_error(r, req_len_arr[i]); 
				check_SSL_write_error(r, strlen(request)+1); 

				#ifdef DEBUG
				printf("[DEBUG] Wrote %d bytes (on slice %d)\n", r, i);
				#endif
			}else{
				// prepare fake request slices if needed  
				if (req_len_arr[i] > 0){
					char *fake_request = (char*) malloc(req_len_arr[i] + 1);
					memset(fake_request, '?', req_len_arr[i]);	
					fake_request[req_len_arr[i]] = 0;
					#ifdef VERBOSE
					printf ("[DEBUG] Prepared padding:\n%s\n", fake_request); 
					#endif
					#ifdef DEBUG
					printf ("[DEBUG] Send padding with slice %d\n", i); 
					#endif 	
					r = SPP_write_record(ssl, fake_request, req_len_arr[i], ssl->slices[i]);
					//r = SPP_write_record(ssl, fake_request, strlen(fake_request), ssl->slices[i]);
					// Check for errors 	
					//check_SSL_write_error(r, req_len_arr[i]); 
					check_SSL_write_error(r, strlen(fake_request)); 

					// logging 			
					#ifdef DEBUG
					printf("[DEBUG] Wrote %d bytes (on slice %d)\n", r, i);
					#endif
					// free memory 
					free(fake_request); 

				}
			
			}
		}
	}
	// SSL write
	else if (strcmp(proto, "ssl") == 0){
		#ifdef DEBUG
		printf("[DEBUG] SSL_write\n");
		#endif 
		//r = SSL_write(ssl, request, request_len);
		r = SSL_write(ssl, request, strlen(request));
		//check_SSL_write_error(r, request_len); 
		check_SSL_write_error(r, strlen(request)); 
	}
	// socket write
	else if (strcmp(proto, "pln") == 0){
		#ifdef DEBUG
		printf("[DEBUG] Plain socket write\n");
		#endif 
	    //r = write(plain_socket, request, strlen(request));
	    r = write(plain_socket, request, request_len);
		experiment_info->app_bytes_written += r;
	    if ( r <= 0 ){
			printf("[ERROR] Something went wrong with writing to the socket!\n");
	    }
	    #ifdef DEBUG
		printf("[DEBUG] Request sent. %d bytes\n", r);
		#endif 
	}

	// free memory 
	free(padding); 
	free(request); 

}





// Form and send GET
void sendRequest(char *filename){
		
	char request[200];
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
		// Use slice 0 as default for sending (HEADER)
		int r = SPP_write_record(ssl, request, request_len, ssl->slices[0]);
		#ifdef DEBUG
		printf("[DEBUG] Wrote %d bytes\n", r);
		#endif
		check_SSL_write_error(r, request_len); 
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
		experiment_info->app_bytes_written += r;
	    if ( r <= 0 )
	    {
	    	printf("Something went wrong with writing to the socket!\n");
	    }
	    #ifdef DEBUG
		printf("[DEBUG] Request sent. %d bytes\n", r);
		#endif 
		
	}

}



// Read file line by line with timing information 
static void *browser_replay(void *ptr){
	char line[300];
	//int previous_time = 0;      // current/previous time
	FILE *fp;                   // pointer to file
	int curr_line = 0;       // keep track of line read 

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
    while ( fgets ( line, sizeof line, fp ) != NULL &&  curr_line < lines) {
		double time;
		//double duration; 
		char file_request[128]; 
	
		// Current line read in the file
		curr_line ++; 
		
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

		/* Original code to relay timing information from traces
		// Compute sleeping time 
		double time_to_sleep = time - previous_time; 
		#ifdef DEBUG
		printf("[DEBUG] Sleeping for %f\n", time_to_sleep); 
		#endif 
    	sleep(time_to_sleep);
	
		*/ 

		// Send HTTP GET 
		#ifdef DEBUG
		printf("[DEBUG] Sending GET request for <<%s>> bytes of data\n", file_request); 
		#endif 
		
		if (curr_line == lines){
			#ifdef DEBUG
			printf("[DEBUG] File has %d GET and we sent %d. Reading thread is done\n", lines, curr_line); 
			#endif 
			running = false; 
		}
		sendRequestBrowser(file_request); 
		
		// Wait on main thread to have received requested data unless we are done 
		if (curr_line < lines){
			thr_join(); 
		}
		done = 0;  
		
		/* Not used 
		// Save current time
		previous_time = time;  
		*/
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
static int http_complex(char *proto, char *fn, struct timeval *tvEnd){

	int r; 
	char buf[BUFSIZZ];
	long bytes_read = 0;

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
		} 
		// SSL read
		else if (strcmp(proto, "ssl") == 0){
			#ifdef DEBUG
			printf("[DEBUG] Waiting on SSL_read...\n");
			#endif 
			r = SSL_read(ssl, buf, BUFSIZZ);
		}
		// TCP read 		
		else if (strcmp(proto, "pln") == 0){
			r = read(plain_socket, buf, BUFSIZZ);
			experiment_info->app_bytes_read += r;
		}
		// Check for errors in read 
		if (strcmp(proto, "spp") == 0 || strcmp(proto, "ssl") == 0){
			switch(SSL_get_error(ssl, r)){
				case SSL_ERROR_NONE:			break;
				case SSL_ERROR_ZERO_RETURN:		berr_exit("SSL error zero return");
				case SSL_ERROR_SYSCALL: 		berr_exit("SSL Error: Premature close");
				default:						berr_exit("SSL read problem");
			}
		}

		#ifdef DEBUG
		printf("Read %d bytes\n", r);
		#endif

		// Write buf to stdout
		#ifdef VERBOSE
		printf("[DEBUG] Received:\n%s\n\n", buf); 
		#endif 
    	
		// Update counter of bytes read 
		bytes_read += r;
		
		//if ( r <= 0 || bytes_read == fSize){
		#ifdef DEBUG
		printf("[DEBUG] File transfer stats %d -- %ld\n", bytes_read,  fSize); 
		#endif 
		if (bytes_read == fSize){
			#ifdef DEBUG
			printf("[DEBUG] File transfer done - signaling to other thread\n");
			#endif 
			bytes_read = 0; 
			if (running){
				thr_exit();
			}else{
				#ifdef DEBUG
				printf("[DEBUG] Reading thread is done, so here we are done too\n"); 
				#endif
				break;  
			} 
		}
	}
    
	// Measure time
	gettimeofday(tvEnd, NULL);
	
	// Shutdown connection 
	#ifdef DEBUG
	printf("[DEBUG] Shutdown was requested -- HERE\n"); 
	#endif 
	r = SSL_shutdown(ssl);
	if( !r ){
			shutdown(SSL_get_fd(ssl), 1);
			r = SSL_shutdown(ssl);
		}


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
	long bytes_read = 0;
    // Compute expected data size
	fSize = atoi(filename);
    if (fSize == 0 && filename[0] != '0'){
		if (requestingFile){
			fSize = calculate_file_size(filename);
		}else{
	    	fSize = strlen("HTTP/1.0 200 OK\r\n"); 
		}
	}   
	sizeCheck = fSize; 
	experiment_info->file_size = fSize;

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
			if (ssl->read_stats.app_bytes == fSize){
				printf("[INFO] Read %d bytes as expected (fSize=%d). Stopping timer\n", ssl->read_stats.app_bytes, fSize);
				// Stop the timer here (avoid shutdown crap) 
				gettimeofday(tvEnd, NULL); 
				#ifdef VERBOSE
				fwrite(buf, 1, len, stdout);
				#endif
				break; 
				//goto shutdown;
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
			if (ssl->read_stats.app_bytes == fSize){
				printf("[INFO] Read %d bytes as expected (fSize=%d). Stopping timer\n", ssl->read_stats.app_bytes, fSize);
				gettimeofday(tvEnd, NULL);
				// Write buf to stdout
				#ifdef VERBOSE
				fwrite(buf, 1, len, stdout);
				#endif
				break; 
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
			#ifdef DEBUG 
			printf("[DEBUG] Waiting to read bytes in plain mode\n");
			#endif
			r = read(plain_socket, buf, BUFSIZZ);
			experiment_info->app_bytes_read += r;
			bytes_read += r;
			#ifdef DEBUG 
			printf("[DEBUG] Read %d bytes\n", r);
			#endif
			if ( r <= 0 || bytes_read == fSize) /* done reading */
			{
				#ifdef DEBUG
				printf("[DEBUG] File transfer done, done reading socket...\n"); 
				#endif 
				gettimeofday(tvEnd, NULL);
				// Write buf to stdout
				#ifdef VERBOSE
				fwrite(buf, 1, len, stdout);
				#endif 
				goto done;
			}
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
		if( !r ){
			shutdown(SSL_get_fd(ssl), 1);
			r = SSL_shutdown(ssl);
		}

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
	int total_read, total_write, app_read, app_write;
	if (strcmp(proto, "pln") == 0) {
		total_read = app_read = experiment_info->app_bytes_read;
		total_write = app_write = experiment_info->app_bytes_written;
	} else {
		total_read = s->read_stats.bytes;
		total_write = s->write_stats.bytes;
		app_read = s->read_stats.app_bytes;
		app_write = s->write_stats.app_bytes;
	}

    printf("[RESULTS] BYTE STATISITICS:\n");
    printf("[RESULTS] Bytes read: %d\n", total_read);
    printf("[RESULTS] Application bytes read: %d [Expected %d]\n", app_read, sizeCheck); 
    printf("[RESULTS] Block padding bytes read: %d\n", s->read_stats.pad_bytes);
    printf("[RESULTS] Header bytes read: %d\n", s->read_stats.header_bytes);
    printf("[RESULTS] Handshake bytes read: %d\n", s->read_stats.handshake_bytes);
    printf("[RESULTS] MAC bytes read: %d\n", s->read_stats.mac_bytes);
    printf("[RESULTS] Alert bytes read: %d\n", s->read_stats.alert_bytes);
    printf("[RESULTS] Bytes write: %d\n", total_write);
    printf("[RESULTS] Application bytes write: %d\n", app_write);
    printf("[RESULTS] Block padding bytes write: %d\n", s->write_stats.pad_bytes);
    printf("[RESULTS] Header bytes write: %d\n", s->write_stats.header_bytes);
    printf("[RESULTS] Handshake bytes write: %d\n", s->write_stats.handshake_bytes);
    printf("[RESULTS] MAC bytes write: %d\n", s->write_stats.mac_bytes);
    printf("[RESULTS] Alert bytes write: %d\n", s->write_stats.alert_bytes);

	// In one line (so it's easy for plotting script).
	// num_slices num_mboxes file_size total app_total padding_total header_total handshake_total MAC_total alert_bytes
	printf("[RESULTS] ByteStatsSummary %d %d %d %d %d %d %d %d %d %d\n",
		experiment_info->num_slices,
		experiment_info->num_proxies,
		experiment_info->file_size,
		total_read + total_write,
		app_read + app_write,
		s->read_stats.pad_bytes + s->write_stats.pad_bytes,
		s->read_stats.header_bytes + s->write_stats.header_bytes,
		s->read_stats.handshake_bytes + s->write_stats.handshake_bytes,
		s->read_stats.mac_bytes + s->write_stats.mac_bytes,
		s->read_stats.alert_bytes + s->write_stats.alert_bytes);
}


// Usage function 
void usage(void){
	printf("usage: wclient -s -r -w -i -f -o -a -c -b\n"); 
	printf("-s:   number of slices requested (min 1)\n"); 
	printf("-r:   number of proxies with read access (per slice)\n"); 
	printf("-w:   number of proxies with write access (per slice)\n"); 
	printf("-i:   integrity check\n"); 
	printf("-f:   file for http GET (either via <name> (require file to exhist both at server and client[for testing reasons]) or via <size>)\n"); 
	printf("-o:   {1=test handshake ; 2=200 OK ; 3=file transfer ; 4=browser-like behavior}\n");
	printf("-a:   action file for browser-like behavior\n");
	printf("-c:   protocol chosen (ssl ; spp; pln; fwd; spp-mod; ssl-mod; fwd-mod; pln-mod)\n"); 
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
	SPP_PROXY **proxies;                   // proxy array 
	int N_proxies = 0;                     // number of proxies in path 
	int action = 0;                        // specify client/server behavior (handshake, 200OK, serve file, browser-like)
	char *file_action = NULL;              // file action to use for browser-liek behavior
	struct timeval tvBeginConnect; 
	struct timeval tvEndConnect; 
	struct timeval tvBegin, tvEnd; 
	struct timeval tvConnect, tvDuration;  // time structures for handshake duration 
	experiment_info = (ExperimentInfo*)malloc(sizeof(ExperimentInfo));
	experiment_info->app_bytes_read = 0;
	experiment_info->app_bytes_written = 0;

#ifdef DEBUG
	printf("\n\n******************** CLIENT STARTING ********************\n");
#endif

	
	// Handle user input parameters
	while((c = getopt(argc, argv, "s:r:w:i:f:c:o:a:b:")) != -1){
			
			switch(c){
	
			// Number of slices
			case 's':	if(! (slices_len = atoi(optarg) )){
							err_exit("Bogus number of slices specified (no. of slices need to be > 1)");
						}
						experiment_info->num_slices = slices_len;
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
						if (strcmp(proto, "spp_mod") == 0){
                  			proto = "spp"; 
                  			disable_nagle = 1;
						}
						if (strcmp(proto, "ssl_mod") == 0){
                  			proto = "ssl"; 
                  			disable_nagle = 1;
						}
						if (strcmp(proto, "fwd_mod") == 0){
                  			proto = "fwd"; 
                  			disable_nagle = 1;
						}
						if (strcmp(proto, "pln_mod") == 0){
                  			proto = "pln"; 
                  			disable_nagle = 1;
						}
						if (strcmp(proto, "fwd") == 0){
                  			proto = "ssl"; 
						}
						break; 
			
			// File requested for HTTP GET
			case 'f':	if(! (file_requested = strdup(optarg) )){
							err_exit("Out of memory");
						}
						break; 

			// Client/Server behavior 
			case 'o':	action = atoi(optarg); 
						if (action == 2)
						{
							action = 3;
							file_requested = "1";
						}
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
	experiment_info->num_proxies = N_proxies - 1;
	
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
		printf("Protocol type specified (%s) is not supported. Supported protocols are: spp, ssl, pln\n", proto); 
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
		}else{
			FILE *fp;                   
    		fp = fopen(file_action,"r");  
    		int ch=0;
			// Check for errors while opening file
		    if(fp == NULL){
    		    printf("Error while opening file %s.\r\n", file_action);
        		exit(-1);
			}
			while( ! feof(fp)){
				ch = fgetc(fp);
				if(ch == '\n'){
					lines++;
				}
			}
    		fclose(fp);
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

	// Start timer for SPP (do not count slice creation for SSL instead) 
	if (strcmp(proto, "spp") == 0){
		gettimeofday(&tvBegin, NULL);
	}

	// Create slices_n slices with incremental purpose 
	slice_set  = malloc( slices_len * sizeof (SPP_SLICE*));
	#ifdef DEBUG
	printf("[DEBUG] Generating %d slices\n", slices_len); 
	#endif
	int i; 
	for (i = 0;  i < slices_len; i++){
		char *newPurpose;  
		char str[30]; 
		sprintf (str, "slices_%d", (i + 2)); 
		newPurpose = (char *)malloc(strlen(str)+1);    
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
	
	// Start timer for "ssl" and "pln" 
	if (strcmp(proto, "ssl") == 0 || strcmp(proto, "pln") == 0){
		gettimeofday(&tvBegin, NULL);
	}
	
	// TCP Connect
	char* address = (char*)malloc(strlen(proxies[0]->address) + 1); // Large enough for string+\0
	memcpy(address, proxies[0]->address, strlen(proxies[0]->address) + 1);
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
    }
	
	// SSL Connect 
	gettimeofday(&tvBeginConnect, NULL);

	if (strcmp(proto, "pln") != 0){
		doConnect (proto, slices_len, N_proxies, slice_set, proxies);
	}

	// Measure duration of "ssl"/"spp" connect (it does not apply to "pln" of course) 
	gettimeofday(&tvEndConnect, NULL);
	timeval_subtract(&tvConnect, &tvEndConnect, &tvBegin);
	
	// Switch across possible client-server behavior
	// // NOTE: here we can add more complex strategies
	switch(action){
		// Handshake only 
		case 1:		break; 
                
		// Send simple request, wait for 200 OK
		case 2:		http_request(file_requested, proto, false, &tvEnd);
					break; 

		// Send HTTP GET request and wait for file to be received
		case 3:		http_request(file_requested, proto, true, &tvEnd);
					break; 

		// Send several GET request following a browser-like behavior  
		case 4:		http_complex(proto, file_action, &tvEnd);
					break; 
 
		// Unknown option 
		default:	usage();
					break; 
	}
	// Compute duration of action
	if (action > 1){
		timeval_subtract(&tvDuration, &tvEnd, &tvBegin);
	}

	// Remove SSL context
    destroy_ctx(ctx);
    
	// Clode socket
    close(sock);

	//Free memory 
	#ifdef DEBUG
	printf("[DEBUG] Freeing memory\n"); 
	#endif 
	for (i = 0; i < N_proxies ; i++){
	    free(proxies[i]);
	}
	for (i = 0; i < slices_len; i++){
		free(slice_set[i]); 
	}
	free(proxies); 
	free(slice_set); 
	free(experiment_info);

	// Report time statistics
	if (action > 1){
		printf("[RESULTS] No_Slices %d Action %s_%d Duration %ld.%06ld\n", slices_len, temp_str, sizeCheck, tvDuration.tv_sec, tvDuration.tv_usec);	
	}else{
		printf("[RESULTS] No_Slices %d Action %s Handshake_Dur %ld.%06ld\n", slices_len, temp_str, tvConnect.tv_sec, tvConnect.tv_usec);	
	}
	
	// All good
	return 0; 
}
