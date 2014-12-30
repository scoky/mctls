/* A simple HTTPS client

   It connects to the server, makes an HTTP
   request and waits for the response
*/
#include <stdbool.h>
#include "common.h"
#define KEYFILE "client.pem"
#define PASSWORD "password"
#define DEBUG

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
void read_proxy_list(char *file_name, SPP_PROXY **array, SSL *ssl){
   	FILE *fp;					// pointer to file
	int count = 0;				// simple counters
	bool firstLine = 1; 		// flag for first line in file
	char line [128];			// maximum size of line to read from 

	// Open file for reading
    fp = fopen(file_name,"r");	
   
	// CHheck for errors while opening file
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
		array[count] = SPP_generate_proxy(ssl, newLine);
		#ifdef DEBUG
		printf("Proxy %d stored has address: %s\r\n", count, array[count]->address);
		count++; 
		int j; 
		for (j = 0; j < count; j++) 
			printf("Previous proxy was %s\r\n",  array[j]->address);
		#endif
    }
	
	// Close file
    fclose(fp);
}

// Function to read a proxy list from file and populate array of proxies
void print_proxy_list(SPP_PROXY **array, int N){
	int i; 
	
	printf("Print proxy list. There are %d available proxies.\r\n", N); 
	for (i = 0; i < N; i++){
		printf("Proxy %d -- %s\r\n", i, array[i]->address);
	}
}

int tcp_connect(host,port)
  char *host;
  int port;
  {
    struct hostent *hp;
    struct sockaddr_in addr;
    int sock;
    
	if(!(hp=gethostbyname(host))){
		berr_exit("Couldn't resolve host");
	}
    memset(&addr,0,sizeof(addr));
    addr.sin_addr=*(struct in_addr*)
      hp->h_addr_list[0];
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);

    if((sock=socket(AF_INET,SOCK_STREAM,
      IPPROTO_TCP))<0)
      err_exit("Couldn't create socket");
    if(connect(sock,(struct sockaddr *)&addr,
      sizeof(addr))<0)
      err_exit("Couldn't connect socket");
    
    return sock;
  }

/* Check that the common name matches the
   host name*/
void check_cert(ssl,host)
  SSL *ssl;
  char *host;
  {
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
    X509_NAME_get_text_by_NID
      (X509_get_subject_name(peer),
      NID_commonName, peer_CN, 256);


      // WARNING NO VALIDATION Validate the hostname
  if (1) {
    
      printf("Peer_CN = %s\n", peer_CN);
      printf("Host = %s\n\n", host);
      //err_exit("Common name doesn't match host name");
    }
  }


   

static char *REQUEST_TEMPLATE=
   "GET / HTTP/1.0\r\nUser-Agent:"
   "EKRClient\r\nHost: %s:%d\r\n\r\n";

static char *host=HOST;
static int port=PORT;
static int require_server_auth=1;

static int http_request(ssl)
  SSL *ssl;
  {
    char *request=0;
    char buf[BUFSIZZ];
    int r;
    int len, request_len;
    
    /* Now construct our HTTP request */
    request_len=strlen(REQUEST_TEMPLATE)+
      strlen(host)+6;
    if(!(request=(char *)malloc(request_len)))
      err_exit("Couldn't allocate request");
    snprintf(request,request_len,REQUEST_TEMPLATE,
      host,port);

    /* Find the exact request_len */
    request_len=strlen(request);

    r=SSL_write(ssl,request,request_len);
    switch(SSL_get_error(ssl,r)){      
      case SSL_ERROR_NONE:
        if(request_len!=r)
          err_exit("Incomplete write!");
        break;
        default:
          berr_exit("SSL write problem");
    }
    
    /* Now read the server's response, assuming
       that it's terminated by a close */
    while(1){
      r=SSL_read(ssl,buf,BUFSIZZ);
      switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
          len=r;
          break;
        case SSL_ERROR_ZERO_RETURN:
          goto shutdown;
        case SSL_ERROR_SYSCALL:
          fprintf(stderr,
            "SSL Error: Premature close\n");
          goto done;
        default:
          berr_exit("SSL read problem");
      }

      fwrite(buf,1,len,stdout);
    }
    
  shutdown:
    r=SSL_shutdown(ssl);
    switch(r){
      case 1:
        break; /* Success */
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

// Usage
void usage(void){
	printf("usage: wclient -h -p -s -r -w -i\n"); 
	printf("-h: name of host to connect to\n"); 
	printf("-p: port of host to connect to\n"); 
	printf("-s: number of slices requested\n"); 
	printf("-r: number of proxies with read access (per slice)\n"); 
	printf("-w: number of proxies with write access (per slice)\n"); 
	printf("-i: ??\n"); 
	exit(-1);  
}


// Main goes here     
int main(int argc, char **argv){
	SSL_CTX *ctx;						// SSL context
	SSL *ssl;							// SSL context
	BIO *sbio;							// ?
	int sock;							// socket
	extern char *optarg;				// user input parameters
	int c;								// ?
	int N_proxies = 0;					// number of proxies indicated
	char *filename = "proxyList"; 		// filename for proxy
	int S = 0, r = 0, w = 0;			// slice related parameters

	// Handle user input parameters
	while((c = getopt(argc, argv, "h:p:s:r:w:i")) != -1){
			
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
				if(! (S = atoi(optarg) ))
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

        	// ??
			case 'i':
				require_server_auth = 0;
				break; 
      		
			// default case 
			default:
				usage(); 
				break; 
		}
    }

	// Check input parameters are correct 
	printf("Parameters count: %d\n", argc); 
	if (argc == 1){
		usage(); 
	}
	
	// Read number of proxy from file 
	N_proxies = read_proxy_count(filename); 
	printf("INPUT host=%s port=%d slices=%d read=%d write=%d n_proxies=%d\n", host, port, S, r, w, N_proxies); 
	if (r > N_proxies || w > N_proxies){
		printf ("Check your values for r and w\n"); 
		usage(); 
	}
	SPP_PROXY *array[N_proxies]; 

	// Logging 
	printf("Host: %s, port %d\n", host, port);

    // Build our SSL context
	ctx = initialize_ctx(KEYFILE, PASSWORD);

	// Connect the TCP socket
	sock = tcp_connect(host, port);
	
	// Connect the SSL socket 
	ssl = SSL_new(ctx);
	sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);

	// Create slices -- simple 
	int i; 
	SPP_SLICE *slice_set[S];
	#ifdef DEBUG
	printf("Generating %d slices\n", S); 
	#endif
	for (i = 0;  i < S; i++){
		char str[30]; 
		sprintf (str, "slices_%d", i); 
		slice_set[i] = SPP_generate_slice(ssl, str); 
		#ifdef DEBUG
		printf("Generated slices %d with purpose %s\n", slice_set[i]->slice_id, slice_set[i]->purpose); 
		#endif
	}

	// Read proxy list 
	read_proxy_list(filename, array, ssl);

	// Print proxy list 
	#ifdef DEBUG
	print_proxy_list(array, N_proxies); 
	#endif
	
	// Assign write access to proxies for all slices 
	// Find MAX between r and w
	int MAX = r; 
	if (w > r) 
		MAX = w; 
		
	// Iterate among proxies
	for (i = 0; i < MAX ; i++){
		
		// assign read access if requested
		if (i < r){
			if (SPP_assign_proxy_read_slices(ssl, array[i], *slice_set, S) == 1 ) {
				#ifdef DEBUG
				printf ("Proxy %s correctly assigned read access to slice-set (READ_COUNT=%d)\n", array[i]->address, (i + 1)); 
				#endif
			}
		}

		// assign write access if requested
		if (i < w){
			if (SPP_assign_proxy_write_slices(ssl, array[i], *slice_set, S) == 1 ) {
				#ifdef DEBUG
				printf ("Proxy %s correctly assigned write access to slice-set (WRITE COUNT=%d)\n", array[i]->address, (i + 1)); 
				#endif
			}
		}
	}

    // Do a simple connect here 
	if(SSL_connect(ssl)<=0)
      berr_exit("SSL connect error");
    if(require_server_auth)
      check_cert(ssl,host);
 
    // Make HTTP request -- TO DO:  extend by passing filename!
    http_request(ssl);

    // Shutdown the socket
    destroy_ctx(ctx);
    close(sock);

	//Free array of proxies 
	for (i = 0; i < N_proxies ; i++){
	    free(array[i]);
	}
	
	// All done
    exit(0);
  }

