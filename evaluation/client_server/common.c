#include "common.h"

BIO *bio_err=0;
static char *pass;
static int password_cb(char *buf,int num, int rwflag,void *userdata);
static void sigpipe_handle(int x);

/* A simple error and exit routine*/
int err_exit(string)
  char *string;
  {
  	#ifdef DEBUG
    printf("[ERROR] %s\n",string);
	#endif

    fprintf(stderr,"%s\n",string);
    exit(0);
  }

/* Print SSL errors and exit*/
int berr_exit(string)
  char *string;
  {
    #ifdef DEBUG
	BIO_printf(bio_err,"%s\n",string);
    ERR_print_errors(bio_err);
	#endif
    exit(0);
  }

/*The password code is not thread safe*/
static int password_cb(char *buf,int num,
  int rwflag,void *userdata)
  {
    if(num<strlen(pass)+1)
      return(0);

    strcpy(buf,pass);
    return(strlen(pass));
  }

static void sigpipe_handle(int x){
}


// Initialize context
SSL_CTX *initialize_ctx(char *keyfile, char *password, char *proto){
    SSL_METHOD *meth;
    SSL_CTX *ctx;
    
    if(!bio_err){
      /* Global system initialization*/
      SSL_library_init();
      SSL_load_error_strings();
      
      /* An error write context */
      bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    }

    /* Set up a SIGPIPE handler */
    signal(SIGPIPE,sigpipe_handle);
    
    /* Create our context*/
	if (strcmp(proto, "ssl") == 0){		
   		#ifdef DEBUG
		printf("[DEBUG] Using TLSv1_2_method\n");  
		#endif
		meth = TLSv1_2_method();  
		//meth = SSLv23_method();
	} else if (strcmp(proto, "middlebox") == 0){  
   		#ifdef DEBUG
   		printf("[DEBUG] Using SPP_proxy_method (only middleboxes should use this)\n");  
		#endif 
		meth = SPP_proxy_method();
	}
	else {
   		#ifdef DEBUG
   		//printf("[DEBUG] Using SPP_method\n");  
		#endif 
		meth = SPP_method(); 
	}

    ctx = SSL_CTX_new(meth);

    /* Specify the cipher suites that may be used. */
	
    if (!SSL_CTX_set_cipher_list(ctx, "DHE-RSA-AES128-SHA256")) {
	printf("Failed seting cipher list.\n");
    }
	

    /* Load our keys and certificates*/
    if(!(SSL_CTX_use_certificate_chain_file(ctx,
      keyfile)))
      berr_exit("Can't read certificate file");

    pass=password;
    SSL_CTX_set_default_passwd_cb(ctx,
      password_cb);
    if(!(SSL_CTX_use_PrivateKey_file(ctx,
      keyfile,SSL_FILETYPE_PEM)))
      berr_exit("Can't read key file");

    /* Load the CAs we trust*/
    if(!(SSL_CTX_load_verify_locations(ctx,
      CA_LIST,0)))
      berr_exit("Can't read CA list");
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
    SSL_CTX_set_verify_depth(ctx,1);
#endif
    
    return ctx;
  }
     
void destroy_ctx(ctx)
  SSL_CTX *ctx;
  {
    SSL_CTX_free(ctx);
  }

void set_nagle(int sock, int flag) {
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
}

// tokenizer helper 
int TokenizeString(char *s_String, char ***s_Token, int *size, char c_Delimiter){
    int token_count = 0, max_token_size = 0, token_size = 0;
    int j = 0; 
    unsigned int i_Offset = 0; 
    char b_Flag = 0; 
    int count = 0; 
    char *c;

    // Get the number of tokens and the maximum token size
    for (c = s_String;; c++) {
	if ((*c) != c_Delimiter && (*c) != '\t' && (*c) != '\n' && (*c) != '\0') {
	   token_size++;
	   continue;
	}
	if (token_size > 0) {
	   max_token_size = max_token_size > token_size+1 ? max_token_size : token_size+1;
	   token_size = 0;
	   token_count += 1;
	}
	if ((*c) == '\0') {
	   break;
	}
    }
    #ifdef DEBUG
    printf("TokenizeString: token_count=%d, max_token_size=%d\n", token_count, max_token_size);
    #endif
    (*size) = max_token_size;
    (*s_Token) = (char**)malloc(token_count);
    for (j = 0; j < token_count; j++) {
	(*s_Token)[j] = (char*)malloc(max_token_size);
    }

    for (i_Offset = 0;s_String[i_Offset] != '\0';i_Offset++){
	#ifdef DEBUG
	printf("TokenizeString: char=%c\n", s_String[i_Offset]);
	#endif
        if (s_String[i_Offset] != c_Delimiter && s_String[i_Offset] != '\t' && s_String[i_Offset] != '\n' && s_String[i_Offset] != '\0'){
            ((*s_Token)[count])[j] = s_String[i_Offset];
            j++;
	    if (j >= max_token_size) {
		printf("TokensizeString: token too long! exceeds 15 characters including nul terminator.\n");
	    }
            b_Flag = 1; 
            continue;
        }
        if (b_Flag){
	if (count >= token_count) {
		printf("TokenizeString: too many tokens! exceeds limit of 50 tokens.\n");
	}
        ((*s_Token)[count])[j] = '\0';
	#ifdef DEBUG
	printf("TokenizeString: token=%s\n", (*s_Token)[count]);
	#endif
        count++;
        j = 0; 
        b_Flag = 0; 
        }
    }
    if (b_Flag || j > 0) {
        ((*s_Token)[count])[j] = '\0';
	#ifdef DEBUG
	printf("TokenizeString: token=%s\n", (*s_Token)[count]);
	#endif
        count++;
    }
    return count;
}

