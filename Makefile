all: key server client

key:
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout mycert.pem -out mycert.pem

server:
	gcc -Wall -o server server.c -L/usr/lib -lssl -lcrypto

client: 
	gcc -Wall -o client client.c -L/usr/lib -lssl -lcrypto

clean:
	rm -f client server mycert.pem