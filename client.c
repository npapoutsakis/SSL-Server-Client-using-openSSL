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
        printf("eeede");
        abort();
    }
    
    int sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);    

    //Host's address
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    //Open a connection on socket sd, returns 0 if success
    if(connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0){
        perror(hostname);
        abort();
        //Close the file descriptor/socket
        close(sd);
    }

    return sd;
}

SSL_CTX* InitCTX(void)
{
    //Similar to initServerCTX
    /* Load cryptos, et.al. */
    OpenSSL_add_all_algorithms();
    
    /* Bring in and register error messages */
    SSL_load_error_strings();

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

void ShowCerts(SSL* ssl)
{   
    //allocate an empty X509 object
    X509 *cert = X509_new();

	/* get the server's certificate */ // or get_peer_certificate()?
    cert = SSL_get_peer_certificate(ssl);    

    //HELPFUL DOC: https://zakird.com/2013/10/13/certificate-parsing-with-openssl
    if (cert != NULL)
    {
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

    //registers the available SSL/TLS ciphers and digests. -> always returns 1
    SSL_library_init();

    //Init ctx, so that we can make an ssl connection
    SSL_CTX *ctx = InitCTX();

    //Open connection
    int server_id = OpenConnection(strings[1], atoi(strings[2])); //atoi used to convert the string into integer

    /* create new SSL connection state */ 
    //Now that we have both the context and the socket id, just create the ssl structure
    SSL *ssl = SSL_new(ctx);
      
    /* attach the socket descriptor */
	SSL_set_fd(ssl, server_id);

    /* perform the connection */
    if (SSL_connect(ssl) == FAIL)   /* connection fail */
        ERR_print_errors_fp(stderr);
    else
    {
        char acUsername[16] = {0};
        char acPassword[16] = {0};
        const char *cpRequestMessage = "<Body>\
                               <UserName>%s<UserName>\
                 <Password>%s<Password>\
                 <\Body>";

        printf("Enter the User Name : ");
        scanf("%s",acUsername);
        
        printf("\n\nEnter the Password : ");
        scanf("%s",acPassword);


        //sprintf can create the string in the format we want https://www.tutorialspoint.com/c_standard_library/c_function_sprintf.htm
        /* construct reply */
        char client_msg_req[1024] = {0};
        sprintf(client_msg_req, cpRequestMessage, acUsername, acPassword);
		
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));

   		/* get any certs */
        ShowCerts(ssl);

        //Usefull https://man.openbsd.org/SSL_write.3
        /* encrypt & send message */
        int check = SSL_write(ssl, client_msg_req, sizeof(client_msg_req));
        if(check <= 0){
            fprintf(stderr, "Encryption Failed!\n");
            exit(1);
        }

        /* get reply & decrypt */
        char buffer[1024] = {0};
        int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        
        //The last is null char so set to 0
        buffer[bytes] = 0;
        printf("Received Message:\"%s\"\n", buffer);

        /* release connection state */
        SSL_free(ssl);
        // SSL_shutdown(ssl);
    }

    /* close socket */
	close(server_id);

    /* release context */
    //removes the SSL_CTX object pointed to by ctx and frees up the allocated memory
	SSL_CTX_free(ctx);
    
    return 0;
}
