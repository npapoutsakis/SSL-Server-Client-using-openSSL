#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL    -1

int OpenConnection(const char *hostname, int port)
{
    //Almost the same as the openListener, but on client's side we connect to the socket
    struct sockaddr_in addr;

    //Check if host exists!
    struct hostent *host = gethostbyname(hostname);
    if (host == NULL){
        perror(hostname);
        abort();
    }
    
    int sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);    

    //Host's address
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    //Open a connection on socket sd, returns 0 if success
    connect(sd, (struct sockaddr*)&addr, sizeof(addr));

    if(sd != 0){
        perror(hostname);
        abort();
        //Close the file descriptor/socket
        close(sd);
    }

    return sd;
}

SSL_CTX* InitCTX(void)
{
    //Similarities with initServerCTX
    /* Load cryptos, et.al. */
    OpenSSL_add_ssl_algorithms();
    
    /* Bring in and register error messages */
    ERR_load_crypto_strings();

	/* Create new client-method instance -> no need*/
    //Using TLSv1.2 protocol, TLSv1_2_client_method() returns pointers to CONST static objects
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_client_method()); /* Create new client-method instance and parse*/

    //If null -> abort()
    if (ctx == NULL){
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}

void ShowCerts(const SSL* ssl)
{   
    //allocate an empty X509 object
    X509 *cert = X509_new();

	/* get the server's certificate */ // or get_peer_certificate()?
    cert = SSL_get_certificate(ssl);    

    //HELPFUL DOC: https://zakird.com/2013/10/13/certificate-parsing-with-openssl
    if (cert != NULL)
    {
        printf("Server certificates:\n");
        
        char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
        printf("Subject: %s\n", subj);
    
        char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);    	    
        printf("Issuer: %s\n", issuer);
    
        //Free space occupied from X509_new();
        X509_free(cert);  
    }
    else
        printf("Info: No client certificates configured.\n");

    return;
}

int main(int count, char *strings[])
{
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    /* */
    /* create new SSL connection state */
		/* attach the socket descriptor */
		/* perform the connection */
    if ( SSL_connect(ssl) == FAIL )   /* connection fail */
        ERR_print_errors_fp(stderr);
    else
    {
        char acUsername[16] = {0};
        char acPassword[16] = {0};
        const char *cpRequestMessage = "<Body>\
                               <UserName>%s<UserName>\
                 <Password>%s<Password>\
                 <\\Body>";
        printf("Enter the User Name : ");
        scanf("%s",acUsername);
        printf("\n\nEnter the Password : ");
        scanf("%s",acPassword);
				/* construct reply */
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
   			/* get any certs */
        /* encrypt & send message */
        /* get reply & decrypt */
	      /* release connection state */
    }
		/* close socket */
		/* release context */
    return 0;
}
