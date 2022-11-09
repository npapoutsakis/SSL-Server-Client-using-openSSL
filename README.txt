gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0

#            Systems and Security PLH519
#           
#   Topics: Server-Client communication using OpenSSL
#
#       Author: Nikolaos Papoutsakis 2019030206



In this assignment we created a secure connection between server and client using the TLSv1.2 protocol.
The idea was to implement the SSL handshake authentication process.


Explain arguments of the command: 
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout mycert.pem -out mycert.pem
		
		1. openssl req : 
			creates and processes certificate requests in PKCS#10 format
		
		2. x509: 
			this option outputs a self signed certificate instead of a certificate request
		
		3. nodes: 
			if this option is specified then if a private key is created it will not be encrypted
		
		4. days:
			when the -x509 option is being used this specifies the number of days to certify the certificate for
		
		5. newkey rsa:bits:
			this option creates a new certificate request and a new private key.The argument takes one of several forms. rsa:nbits, where nbits is the number of bits, generates an RSA key nbits in size.
		
		6. keyout:
			this gives the filename to write the newly created private key to. If this option is not specified then the filename present in the configuration file is used.
		
		7. out:
			This specifies the output filename to write to or standard output by default.


Tool Specifications:
	Answers:
		3.a the function isRoot() makes us use this command only with sudo (root, trusted user)
		3.b the number 8082 is the port number that the server will wait for requests
		
		4.a the address 127.0.0.1 is the local host address
		4.b the client now knows that he has to send the request on the port 8082 that the server is waiting
			

Makefile:
	it consists all important files so that we can compile and run the executables
	use the command 'make' to compile the files
	use the command 'make clean' to delete link files and .txt generated
	

Commands to test:
	create certificate:
		openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout mycert.pem -out mycert.pem
	
	run server:
		sudo ./server 8082
	
	run client:	
		./client 127.0.0.1 8082

