/* apps/s_time.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 */

#define NO_SHUTDOWN
//#define DEBUG 

/*-----------------------------------------
   s_time - SSL client connection timer program
   Written and donated by Larry Streepy <streepy@healthcare.com>
  -----------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>			// to support boolean
#include "common.h"				// common library between client and server
#define USE_SOCKETS
#include "apps.h"
#ifdef OPENSSL_NO_STDIO
#define APPS_WIN16
#endif
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include "s_apps.h"
#include <openssl/err.h>
#ifdef WIN32_STUFF
#include "winmain.h"
#include "wintext.h"
#endif
#if !defined(OPENSSL_SYS_MSDOS)
#include OPENSSL_UNISTD
#endif

#undef PROG
#define PROG s_time_main

#undef ioctl
#define ioctl ioctlsocket

#define SSL_CONNECT_NAME	"localhost:4433"

/*#define TEST_CERT "client.pem" */ /* no default cert. */

#undef BUFSIZZ
#define BUFSIZZ 1024*10

#define MYBUFSIZ 1024*8

#undef min
#undef max
#define min(a,b) (((a) < (b)) ? (a) : (b))
#define max(a,b) (((a) > (b)) ? (a) : (b))

#undef SECONDS
#define SECONDS	10
extern int verify_depth;
extern int verify_error;

static void s_time_usage(void);
static int parseArgs( int argc, char **argv );
static SSL *doConnection( SSL *scon, char *proto );
static void s_time_init(void);
static int read_proxy_list(char *, char ** ); 
static int check_SSL_write_error( SSL *, int, int );
static void slices_management( SSL *, SPP_SLICE **, SPP_PROXY ** ); 
static int send_GET_request( SSL * ); 

/***********************************************************************
 * Static data declarations
 */

/* static char *port=PORT_STR;*/
static char *host = SSL_CONNECT_NAME;
static char *t_cert_file = NULL;
static char *t_key_file = NULL;
static char *CApath = NULL;
static char *CAfile = NULL;
static char *tm_cipher = NULL;
static int tm_verify = SSL_VERIFY_NONE;
static int maxTime = SECONDS;
static SSL_CTX *tm_ctx = NULL;
static const SSL_METHOD *s_time_meth = NULL;
static char *s_www_path = NULL;
static long bytes_read = 0; 
static int st_bugs = 0;
static int perform = 0;
#ifdef FIONBIO
static int t_nbio = 0;
#endif
#ifdef OPENSSL_SYS_WIN32
static int exitNow = 0;                    // Set when it's time to exit main
#endif
static int slices_len = 0;                 // Number of slices (spp) 
static int r = 0;                          // Number of proxies with read access (spp)
static int w = 0;                          // Number of proxies with write access (spp)
static char *proto = "ssl";                // Protocol of choice (ssl; spp) 
static int N_proxies = 0;                  // number of proxies indicated
static char *filename = "proxyList";       // filename for proxy
static char **proxies_address;             // array of address for proxies
static bool reuse = false;                 // SSL session caching 
static int socket = 0;


static void s_time_init(void)
	{
	host=SSL_CONNECT_NAME;
	t_cert_file=NULL;
	t_key_file=NULL;
	CApath=NULL;
	CAfile=NULL;
	tm_cipher=NULL;
	tm_verify = SSL_VERIFY_NONE;
	maxTime = SECONDS;
	tm_ctx=NULL;
	s_time_meth=NULL;
	s_www_path=NULL;
	bytes_read=0; 
	st_bugs=0;
	perform=0;

#ifdef FIONBIO
	t_nbio=0;
#endif
#ifdef OPENSSL_SYS_WIN32
	exitNow = 0;		/* Set when it's time to exit main */
#endif
	}

/***********************************************************************
 * usage - display usage message
 */
static void s_time_usage(void){
	static char umsg[] = "\
-time arg     - max number of seconds to collect data, default %d\n\
-verify arg   - turn on peer certificate verification, arg == depth\n\
-cert arg     - certificate file to use, PEM format assumed\n\
-key arg      - RSA file to use, PEM format assumed, key is in cert file\n\
                file if not specified by this option\n\
-CApath arg   - PEM format directory of CA's\n\
-CAfile arg   - PEM format file of CA's\n\
-cipher       - preferred cipher to use, play with 'openssl ciphers'\n\n";

	printf( "usage: s_time <args>\n\n" );

	printf("-connect host:port - host:port to connect to (default is %s)\n",SSL_CONNECT_NAME);
#ifdef FIONBIO
	printf("-nbio         - Run with non-blocking IO\n");
	//printf("-ssl2         - Just use SSLv2\n");
	//printf("-ssl3         - Just use SSLv3\n");
	printf("-bugs         - Turn on SSL bug compatibility\n");
	printf("-new          - Just time new connections\n");
	printf("-reuse        - Just time connection reuse\n");
	printf("-www page     - Retrieve 'page' from the server\n");
	printf("-time         - Test duration\n");
	printf("--------------------------------\n");
    printf("-proto        - Protocol requested [sll ; spp; pln]\n");
	printf("-slice        - Number of slices requested\n"); 
	printf("-proxies      - Number of proxies\n"); 
    printf("-read         - Number of proxies with read access (per slice)\n"); 
    printf("-write        - Number of proxies with write access (per slice)\n");
#endif
	printf( umsg,SECONDS );
}

/***********************************************************************
 * parseArgs - Parse command line arguments and initialize data
 *
 * Returns 0 if ok, -1 on bad args
 */
static int parseArgs(int argc, char **argv){

    int badop = 0;
    verify_depth = 0;
    verify_error = X509_V_OK;

    argc--;
    argv++;

    while (argc >= 1) {
	if (strcmp(*argv,"-connect") == 0){

		if (--argc < 1) goto bad;
		host= *(++argv);

	} else if (strcmp(*argv,"-reuse") == 0){

		perform = 2;
		reuse = true; 

	} else if (strcmp(*argv,"-new") == 0){

		perform = 1;

	} else if( strcmp(*argv,"-verify") == 0) {
	    
		tm_verify=SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE;
	    if (--argc < 1) goto bad;
	    verify_depth = atoi(*(++argv));
	    BIO_printf(bio_err,"verify depth is %d\n",verify_depth);

	} else if( strcmp(*argv,"-cert") == 0) {
	    
		if (--argc < 1) goto bad;
	    t_cert_file = *(++argv);

	} else if( strcmp(*argv,"-key") == 0) {

	    if (--argc < 1) goto bad;
	    t_key_file = *(++argv);

	} else if( strcmp(*argv,"-CApath") == 0) {

	    if (--argc < 1) goto bad;
	    CApath = *(++argv);

	} else if( strcmp(*argv,"-CAfile") == 0) {

	    if (--argc < 1) goto bad;
	    CAfile = *(++argv);

	} else if( strcmp(*argv,"-cipher") == 0) {

	    if (--argc < 1) goto bad;
	    tm_cipher= *(++argv);
	}
#ifdef FIONBIO
	else if(strcmp(*argv,"-nbio") == 0) {

	    t_nbio=1;

	}
#endif
	else if(strcmp(*argv,"-www") == 0) {

		if (--argc < 1) goto bad;
		s_www_path = *(++argv);
		if(strlen(s_www_path) > MYBUFSIZ-100){
			BIO_printf(bio_err,"-www option too long\n");
			badop=1;
		}
	} else if(strcmp(*argv,"-bugs") == 0){

	    st_bugs = 1;

	}

/*
#ifndef OPENSSL_NO_SSL2
	else if(strcmp(*argv,"-ssl2") == 0) {
	    s_time_meth = SSLv2_client_method();
	}
#endif
#ifndef OPENSSL_NO_SSL3
	else if(strcmp(*argv,"-ssl3") == 0) {
	    s_time_meth = SSLv3_client_method();
	}
#endif
*/
	// duration 
	else if( strcmp(*argv,"-time") == 0) {
	    if (--argc < 1) goto bad;
	    maxTime = atoi(*(++argv));
	}

	// protocol type
	else if( strcmp(*argv,"-proto") == 0) {
	    if (--argc < 1) goto bad;
		proto = *(++argv);

		if ((strcmp(proto, "ssl")) == 0){	
		    s_time_meth = TLSv1_2_method();
		} else if ((strcmp(proto, "spp")) == 0){
		    s_time_meth = SPP_method(); 
		} else if ((strcmp(proto, "pln")) == 0){
		    s_time_meth = SSLv3_client_method(); 
		}
		 else {
	    	BIO_printf(bio_err, "Protocol %s not supported\n", proto); 
			goto bad; 
		}
	}

	// number of slices 
	else if( strcmp(*argv,"-slice") == 0) {
	    if (--argc < 1) goto bad;
	    slices_len = atoi(*(++argv));
	}

	// number of proxies with read access
	else if( strcmp(*argv,"-read") == 0) {
	    if (--argc < 1) goto bad;
	    r = atoi(*(++argv));
	}

	// number of proxies with write access
	else if( strcmp(*argv,"-write") == 0) {
	    if (--argc < 1) goto bad;
	    w = atoi(*(++argv));
	}

	else {
	    BIO_printf(bio_err,"unknown option %s\n",*argv);
	    badop=1;
	    break;
	}

	argc--;
	argv++;
    }

    // If no input from the user, perform=3 [2=reuse, 1=new]
	if (perform == 0){
		perform = 3;
	}

	// Exit if a bad option was given 
    if(badop) {
bad:
	s_time_usage();
	return -1;
    }

	// All good here
	return 0; 
}

/***********************************************************************
 * TIME - time functions
 */
#define START	0
#define STOP	1

// Function used to compute CPU (or process) time 
static double tm_Time_F(int s){
	return app_tminterval(s, 1);   //defined in [2833, /apps/appsc]
}

/***********************************************************************
 * Read counter of number of proxies in the provided list 
 */	
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
	
	// Close file
	fclose(fp);

	return N; 
}


/***********************************************************************
 * Read a proxy list from file and populate array of proxies
 */		
//void read_proxy_list(char *, SPP_PROXY **, SSL *); 
int read_proxy_list(char *file_name, char **proxies_address){
   	FILE *fp;					// pointer to file
	int count = 0;				// simple counters
	char line [128];			// maximum size of line to read from 
	bool firstLine = 1; 		// flag for first line in file
	int N; 						// local variable for number of proxies

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
		proxies_address[count] = newLine;
		
		// Move array index
		count++; 
	}
	
	// Close file
	fclose(fp);

	// all good; 
	return N; 
}


/***********************************************************************
 * Print proxy list 
 */	
void print_proxy_list(SPP_PROXY **proxies, int N){
	int i; 
	
	#ifdef DEBUG	
	printf("Print proxy list. There are %d available proxies.\r\n", N);	
	#endif 
	for (i = 0; i < N; i++){
		printf("Proxy %d -- %s\r\n", i, proxies[i]->address);
	}
}


/***********************************************************************
 * Check for SSL_write error (just write at this point)  
 */	
int check_SSL_write_error(SSL *ssl, int r, int request_len){
	
	switch(SSL_get_error(ssl, r)){
		case SSL_ERROR_NONE:
			if(request_len != r){
				printf("Incomplete write!");
				return -1; 
			}
			break;

		default:
			printf("SSL write problem");
			return -1; 
	}
	return 0; 
}

/***********************************************************************
 * Create slices and assign read and write rights to proxies 
 */	

void slices_management(SSL *ssl, SPP_SLICE **slice_set, SPP_PROXY ** proxies){

	// Create slices_n slices with incremental purpose 
	int i; 
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
		printf("[DEBUG] Generated slices %d with purpose %s\n", slice_set[i]->slice_id, slice_set[i]->purpose); 
		#endif
	}

	// Assign write access to proxies for all slices 
	// Find MAX between r and w
	int MAX = max(w, r);
	
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
				printf ("[DEBUG] Proxy %s assigned write access to slice-set (WRITE COUNT=%d)\n", proxies[i]->address, (i + 1)); 
				#endif
			}
		}
	}	
}

/***********************************************************************
 * Send a GET request (ssl and spp)
 */
int send_GET_request(SSL *scon){

		MS_STATIC char buf[1024*8];   //Buffer allocation 
		int i; 
		
		// Logging 
		#ifdef DEBUG
		printf("[DEBUG]  GET %s\n", s_www_path); 
		#endif 

		// Form HTTP GET request 
		BIO_snprintf(buf, sizeof buf, "GET %s HTTP/1.0\r\n\r\n", s_www_path);
		int request_len = strlen(buf); 
			
		// Send HTTP GET request (SPP) 
		if (strcmp(proto, "spp") == 0){	
			for (i = 0; i < scon->slices_len; i++){
				// currently writing same record -- differentiate per record in the future 
				int r = SPP_write_record(scon, buf, request_len, scon->slices[i]);
				if (check_SSL_write_error(scon, r, request_len) < 0){
					return -1;  
				}
			}	 
		}
			
		// Send HTTP GET request (SSL) 
		if (strcmp(proto, "ssl") == 0){
			#ifdef DEBUG
			printf("[DEBUG] Sending GET request %s\n", buf); 
			#endif 
			int r = SSL_write(scon, buf, request_len);
			if (check_SSL_write_error(scon, r, request_len) < 0){
				return -1; 
			}
		}
				// Send HTTP GET request (SSL) 
		if (strcmp(proto, "pln") == 0){
			#ifdef DEBUG
			printf("[DEBUG] Sending GET request (plain) %s\n", buf); 
			#endif 
			int r = write(SSL_get_fd(scon), buf, request_len);
			if (r < 0){
				return -1; 
			}
		}

		// All good
		return 0; 
}

/***********************************************************************
 * Wait GET response (ssl and spp)
 */
int wait_GET_response(SSL* scon){

	MS_STATIC char buf[1024*8];   //Buffer allocation 
	int i = 0; 

	// Wait for HTTP response (SPP)
	if (strcmp(proto, "spp") == 0){				
		SPP_SLICE *slice;    // slice for SPP_read
		SPP_CTX *ctx;        // context pointer for SPP_read
		
		// check error for SSP_read_record
		while ((i = SPP_read_record(scon, buf, sizeof(buf), &slice, &ctx)) > 0){
			bytes_read += i;
			#ifdef DEBUG
			//printf("%s", buf); 
			printf("[DEBUG] GET response received (size=%lu)\n", bytes_read); 
			#endif 
		}
	}
	
	// Wait for HTTP response (SSL)
	if (strcmp(proto, "ssl") == 0){
		// check error for SSP_read_record
		while ((i = SSL_read(scon, buf, sizeof(buf))) > 0){
			bytes_read += i;
			#ifdef DEBUG
			//printf("%s", buf); 
			printf("[DEBUG] GET response received (size=%lu)\n", bytes_read); 
			#endif 
		}
	}
		// Wait for HTTP response (pln)
	if (strcmp(proto, "pln") == 0){
		// check error for SSP_read_record
		while ((i = read(SSL_get_fd(scon), buf, sizeof(buf))) > 0){
			bytes_read += i;
			#ifdef DEBUG
			//printf("%s", buf); 
			printf("[DEBUG] GET response received (size=%lu)\n", bytes_read); 
			#endif 
		}
	}

	// All good 
	return 0; 
}


/***********************************************************************
 * MAIN - main processing area for client
 *			real name depends on MONOLITH
 */
int MAIN(int, char **);

int MAIN(int argc, char **argv){

	double totalTime = 0.0;
	int nConn = 0;
	SSL *scon = NULL;
	long finishtime = 0;
	int ret = 1, i;
	MS_STATIC char buf[1024*8];
	int ver;

	apps_startup();
	s_time_init();

	// Outpur for errors
	if (bio_err == NULL){
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}

/*	
#if !defined(OPENSSL_NO_SSL2) && !defined(OPENSSL_NO_SSL3)
	s_time_meth = SSLv23_client_method();
#elif !defined(OPENSSL_NO_SSL3)
	s_time_meth = SSLv3_client_method();
#elif !defined(OPENSSL_NO_SSL2)
	s_time_meth = SSLv2_client_method();
#endif
*/

	// Parse command line arguments
	if( parseArgs( argc, argv ) < 0 ){
		goto end;
	}

	// Read proxy list 
	N_proxies = read_proxy_count(filename); 
	
	// Quick check on input parameters	
	if (r > N_proxies || w > N_proxies){
		printf ("The values for r and w need to be <= than the number of proxies\n"); 
		goto end; 
	}

	// Logging input parameters
	#ifdef DEBUG
	BIO_printf(bio_err, "[DEBUG] No. slices=%d No. proxies=%d read=%d write=%d proto=%s\n", slices_len, N_proxies, r, w, proto);
	#endif

	// Allocate memory for proxies address
	proxies_address  = malloc( N_proxies * sizeof (char*));
	read_proxy_list(filename, proxies_address); 

	#ifdef DEBUG
	int ii; 
	for (ii = 0; ii < N_proxies; ii++){
		printf("\t[DEBUG] Proxy %d: %s\n", ii, proxies_address[ii]); 
	}
	#endif

	
	OpenSSL_add_ssl_algorithms();
	if ((tm_ctx = SSL_CTX_new(s_time_meth)) == NULL){
		return(1);
	}

	// Quiet shutdown ...
	SSL_CTX_set_quiet_shutdown(tm_ctx, 1);

	// Set bug options
	if (st_bugs){
		SSL_CTX_set_options(tm_ctx,SSL_OP_ALL);
	}

	// Set cipher as per input 
	SSL_CTX_set_cipher_list(tm_ctx, tm_cipher);

	// Set certificate 
	if(!set_cert_stuff(tm_ctx,t_cert_file,t_key_file)){
		goto end;
	}

	SSL_load_error_strings();

	if ((!SSL_CTX_load_verify_locations(tm_ctx,CAfile,CApath)) || (!SSL_CTX_set_default_verify_paths(tm_ctx))){
		/* BIO_printf(bio_err,"error setting default verify locations\n"); */
		ERR_print_errors(bio_err);
		/* goto end; */
	}

	// If no cipher in input, use default one
	if (tm_cipher == NULL){
		tm_cipher = getenv("SSL_CIPHER");
	}

	// If no cipher at this point, throw an error 
	if (tm_cipher == NULL ) {
		fprintf( stderr, "No CIPHER specified\n" );
	}

    /* [Perform = {2=reuse, 1=new, 3=undefined}]
	if (!(perform & 1)){
		goto next;
	}
	*/
	
	// We are here if -new was used or nothing was specified 
	#ifdef DEBUG
	printf( "[DEBUG] Option=-new Collecting connection statistics for %d seconds\n", maxTime );
	#endif

	// Loop and time how long it takes to make connections
	bytes_read = 0;
	finishtime = (long) time (NULL) + maxTime;
	tm_Time_F(START);

	// Successively open and use connections until time expires
	for (;;){
		// If time is done just break 
		if (finishtime < (long) time (NULL)){
			#ifdef DEBUG
			printf("[DEBUG] Time is up %lu\n", finishtime); 
			#endif 
			break;
		}
		// WIN32 specific stuff
#ifdef WIN32_STUFF
		if( flushWinMsgs(0) == -1 ){
			goto end;
		}

		if( waitingToDie || exitNow ){		/* we're dead */
			goto end;
		}
#endif
		// new connection (no re-use) 

		#ifdef DEBUG
		printf("[DEBUG] Connection %d ", nConn); 
		#endif 
		// Handshake
		if (! reuse){
			#ifdef DEBUG
			printf("(new)\n"); 
			#endif 
			scon = NULL; 
		}else{
			#ifdef DEBUG
			printf("(reuse)\n"); 
			#endif 
		}
		if( (scon = doConnection( scon, proto )) == NULL ){
			goto end;
		}

		// Ask for a file if indicated in input 
		if (s_www_path != NULL) {
			
			// Send GET request 
			if (send_GET_request(scon) < 0){
				printf("Error in sending GET request\n");
				goto end; 
			}
			
			// Wait for GET response 
			if (wait_GET_response(scon) < 0){
				printf("Error in receivign GET response\n");
				goto end; 
			}
		}

#ifdef NO_SHUTDOWN
		#ifdef DEBUG
		printf("[DEBUG] NO SSL shutdown\n"); 
		#endif 
		SSL_set_shutdown(scon, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
#else
		#ifdef DEBUG
		printf("[DEBUG] SSL shutdown\n"); 
		#endif 
		SSL_shutdown(scon);
#endif
		
		#ifdef DEBUG
		printf("[DEBUG] SSL shutdown2 -- ?\n"); 
		#endif 
		SHUTDOWN2(SSL_get_fd(scon));

		nConn += 1;
		if (SSL_session_reused(scon)){
			ver = 'r';
		} else{
			ver = SSL_version(scon);
			if (ver == TLS1_VERSION)
				ver = 't';
			else if (ver == SSL3_VERSION)
				ver = '3';
			else if (ver == SSL2_VERSION)
				ver = '2';
			else
				ver = '*';
		}
		#ifdef DEBUG
		printf("[DEBUG] SSL version=%d\n", ver); 
		#endif 
		fflush(stdout);

		// Free session 
		SSL_free(scon);
		scon = NULL;
	}
	
	totalTime += tm_Time_F(STOP); /* Add the time for this iteration */

	i = (int)((long)time(NULL) - finishtime + maxTime);
	printf( "\n\n%d connections. CPU time=%.2fs; %.2f connections/user sec, bytes read %ld\n", nConn, totalTime, ((double)nConn/totalTime),bytes_read);
	printf( "%d connections in %ld real seconds, %ld bytes read per connection\n",nConn, (long)time(NULL) - finishtime + maxTime, bytes_read/nConn);


/* Now loop and time connections using the same session id over and over
next:
    // [Perform = {2=reuse, 1=new, 3=undefined}]
	if (!(perform & 2)){
		goto end;
	}
	#ifdef DEBUG 
	printf( "[DEBUG] Now timing with session id reuse.\n" );
	#endif 

	nConn = 0;
	totalTime = 0.0;

	finishtime=(long)time(NULL)+maxTime;

	printf( "starting\n" );
	bytes_read=0;
	tm_Time_F(START);
	scon = NULL; 

	for (;;){
		if (finishtime < (long)time(NULL)){
			break;
		}

#ifdef WIN32_STUFF
		if( flushWinMsgs(0) == -1 )
			goto end;

		if( waitingToDie || exitNow )	// we're dead 
			goto end;
#endif

	 	if( (doConnection( scon, proto )) == NULL )
			goto end;
		
		if (s_www_path) {
			// Send GET request 
			if (send_GET_request(scon) < 0){
				printf("Error in sending GET request\n");
				goto end; 
			}
		
			// Receive GET response
			if (wait_GET_response(scon) < 0){
				printf("Error in receiving GET response\n");
				goto end; 
			}

		}

#ifdef NO_SHUTDOWN
		SSL_set_shutdown(scon,SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
#else
		SSL_shutdown(scon);
#endif
		SHUTDOWN2(SSL_get_fd(scon));
	
		nConn += 1;
		if (SSL_session_reused(scon))
			ver='r';
		else
			{
			ver = SSL_version(scon);
			if (ver == TLS1_VERSION)
				ver = 't';
			else if (ver == SSL3_VERSION)
				ver = '3';
			else if (ver == SSL2_VERSION)
				ver = '2';
			else
				ver = '*';
			}
		fflush(stdout);
		}
	totalTime += tm_Time_F(STOP); // Add the time for this iteration

	// Logging 
	printf( "\n\n%d connections in %.2fs; %.2f connections/user sec, bytes read %ld\n", nConn, totalTime, ((double)nConn/totalTime),bytes_read);
	printf( "%d connections in %ld real seconds, %ld bytes read per connection\n",nConn,(long)time(NULL)-finishtime+maxTime,bytes_read/nConn);
	//

	ret=0;
*/

end:
	if (scon != NULL){
		SSL_free(scon);
	}

	if (tm_ctx != NULL){
		SSL_CTX_free(tm_ctx);
		tm_ctx=NULL;
	}

	apps_shutdown();
	OPENSSL_EXIT(ret);
}

/***********************************************************************
 * doConnection - make a connection
 * Args:
 *		scon	= earlier ssl connection for session id, or NULL
 * Returns:
 *		SSL *	= the connection pointer.
 */
static SSL *doConnection(SSL *scon, char *proto){
	BIO *conn;
	SSL *serverCon;
	int width, i;
	fd_set readfds;
	SPP_PROXY *proxies[N_proxies];
	SPP_SLICE *slice_set[slices_len];

	// what is this?
	if ((conn = BIO_new(BIO_s_connect())) == NULL){
		return(NULL);
	}

	BIO_set_conn_hostname(conn, host);

	// Create a new SSL* 
	if (scon == NULL){
		serverCon = SSL_new(tm_ctx);
		if ((strcmp(proto, "spp")) == 0){
			// Assign proxies
			int j; 
			for (j = 0; j < N_proxies; j++){
				proxies[j] = SPP_generate_proxy(serverCon, proxies_address[j]);
				#ifdef DEBUG
				printf("[DEBUG] Generating proxy: %s\n", proxies[j]->address);
				#endif 
			}
			// Generate and assign slices
			slices_management(serverCon, slice_set, proxies); 		
		}
	} 
	// Re-use SSL* passed as argument
	else {
		serverCon = scon;		
		// Get proxies and slices
		int temp_N; 
		int temp_S; 
		SPP_get_proxies(serverCon, proxies, &temp_N); 
		SPP_get_slices(serverCon, slice_set, &temp_S);		
		SSL_set_connect_state(serverCon);
	}

	SSL_set_bio(serverCon, conn, conn);

	// ok, lets connect -- weird 
	for(;;) {
		// Check here 
		if ((strcmp(proto, "spp")) == 0){
			i = SPP_connect(serverCon, slice_set, slices_len, proxies, N_proxies); 
		}
		if ((strcmp(proto, "ssl")) == 0){
			i = SSL_connect(serverCon);
		}		
		if (BIO_sock_should_retry(i)){
			BIO_printf(bio_err,"DELAY\n");

			i = SSL_get_fd(serverCon);
			width = i+1;
			FD_ZERO(&readfds);
			openssl_fdset(i, &readfds);
			/* Note: under VMS with SOCKETSHR the 2nd parameter
			 * is currently of type (int *) whereas under other
			 * systems it is (void *) if you don't have a cast it
			 * will choke the compiler: if you do have a cast then
			 * you can either go for (int *) or (void *).
			 */
			select(width, (void *)&readfds, NULL, NULL, NULL);
			continue;
		}
		break;
	}

	// Negative socket descriptor = error 
	if(i <= 0) {
		BIO_printf(bio_err,"ERROR\n");
		if (verify_error != X509_V_OK){
			BIO_printf(bio_err,"verify error:%s\n", X509_verify_cert_error_string(verify_error));
		} else {
			ERR_print_errors(bio_err);
		}
		if (scon == NULL){
			SSL_free(serverCon);
		}
		return NULL;
	}

	return serverCon;
}


