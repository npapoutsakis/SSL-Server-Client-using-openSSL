#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#define FAIL    -1

// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {   
        return 1;
    }
}

SSL_CTX* InitServerCTX(void)
{
    //Similar to initServerCTX
    /* Load cryptos, et.al. */
    OpenSSL_add_ssl_algorithms();
    
    /* Bring in and register error messages */
    SSL_load_error_strings();

	/* Create new client-method instance -> no need*/
    //Using TLSv1.2 protocol, TLSv1_2_client_method() returns pointers to CONST static objects
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_server_method()); /* Create new client-method instance and parse*/

    //If null -> abort()
    if (ctx == NULL){
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{   
    //Help: https://www.openssl.org/docs/manmaster/man3/SSL_CTX_load_verify_locations.html
    //Its usefull to check if paths and files exist
    //will return 1 if succeed
    int result = SSL_CTX_load_verify_locations(ctx, CertFile, KeyFile);
    if(result != 1){
        ERR_print_errors_fp(stderr);
        abort();
    }
    
    //set default locations for trusted CA certificates
    result = SSL_CTX_set_default_verify_paths(ctx);
    if(result != 1){
        ERR_print_errors_fp(stderr);
        abort();
    }
    
    //Help: https://www.openssl.org/docs/man1.0.2/man3/SSL_CTX_use_certificate.html
    /* set the local certificate from CertFile */
    //will return 1 if succeed
    result = SSL_CTX_use_certificate_chain_file(ctx, CertFile);   
    if(result != 1){
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* set the private key from KeyFile (may be the same as CertFile) */
    result = SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM);   //-> .pem
    if(result != 1){
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* verify private key */
    result = SSL_CTX_check_private_key(ctx);
    if(result != 1){
        ERR_print_errors_fp(stderr);
        abort();
    }

    return;
}

void ShowCerts(SSL* ssl)
{
    //allocate an empty X509 object
    X509 *cert = X509_new();

	/* get the server's certificate */ // or get_peer_certificate()?
    cert = SSL_get_peer_certificate(ssl);    

    //HELPFUL DOC: https://zakird.com/2013/10/13/certificate-parsing-with-openssl
    if (cert != NULL)
    {
        printf("\n"); 
        printf("Server certificates:\n");
        
        //X509_NAME_oneline returns the string dynamically, size ignored
        char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
        if (subj != NULL){
            printf("Subject: %s\n", subj);
        }
        else
            exit(1);
    
        char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);    	    
        if (issuer != NULL){
            printf("Issuer: %s\n", issuer);
        }
        else
            exit(1);

        //Free space occupied from X509_new();
        X509_free(cert);
        printf("\n"); 
    }
    else
        printf("No certificates.\n");
}

void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[1024];
    int sd, bytes;

    const char* ServerResponse="<BODY>\
                               <Name>sousi.com</Name>\
                 <year>1.5</year>\
                 <BlogType>Embedede and c\\c++</BlogType>\
                 <Author>John Johny</Author>\
                 <\BODY>";
    
    const char *cpValidMessage = "<BODY>\
                               <UserName>sousi<UserName>\
                 <Password>123<Password>\
                 <\BODY>";
    
    /* do SSL-protocol accept */   
    if (SSL_accept(ssl) == FAIL) {
        // printf("failed!\n");
        ERR_print_errors_fp(stderr);
    }
    else {
        
        ShowCerts(ssl);
        
        bytes = SSL_read(ssl, buf, sizeof(buf));
        buf[bytes] = '\0';
        printf("Client msg: \"%s\"\n", buf);

        //If nuim of bytes are read, compare the req string with the valid
        if(bytes > 0) {
            //If 0 then correct, response with the authetication success msg
            if(strcmp(cpValidMessage,buf) == 0){
                //print the correct response
                SSL_write(ssl, ServerResponse, strlen(ServerResponse));
            }
            else {
                /*else print "Invalid Message" */
                SSL_write(ssl, "Invalid Message", strlen("Invalid Message"));
            }
        }
        else {
            ERR_print_errors_fp(stderr);    
        }       

        /* get socket connection */
        sd = SSL_get_fd(ssl);        
        
         /* release SSL state */
        SSL_free(ssl);                      
        
        /* close connection */
        close(sd);                      
    }   
    
    return;  
}

int main(int count, char *Argc[])
{
    //Only root user have the permission to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!\n");
        exit(0);
    }
    if (count != 2)
    {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }
    
    // Initialize the SSL library
    SSL_library_init();

    /* initialize SSL */
    SSL_CTX *ctx = InitServerCTX();
    
    /* load certs */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem");
    
    /* create server socket */
    int server_socket = OpenListener(atoi(Argc[1]));
    
    while(1)
    {
		/* accept connection as usual */
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);

        int client = accept(server_socket, (struct sockaddr *)&addr, &len);

        printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		
        /* get new SSL state with context */
        SSL *ssl = SSL_new(ctx);

		/* set connection socket to SSL state */
		SSL_set_fd(ssl, client);

        /* service connection */
        Servlet(ssl);   
    }
    
    /* close server socket */
    close(server_socket);
    
	/* release context */
    SSL_CTX_free(ctx);
    
    return 0;
}
