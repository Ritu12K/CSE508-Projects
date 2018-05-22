
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>


#define BUF_SIZE 4096

struct counter_state {
	unsigned char ivec[AES_BLOCK_SIZE];
	unsigned int num;
	unsigned char ecount[AES_BLOCK_SIZE];
};

char* read_file(const char* filename) {
	char *buffer = 0;
	long length;
	FILE *f = fopen (filename, "rb");

	if (f) {
		fseek (f, 0, SEEK_END);
		length = ftell (f);
		fseek (f, 0, SEEK_SET);
		buffer = malloc (length);
		if (buffer)
		fread (buffer, 1, length, f);
		fclose (f);
	}
	else {
			return 0;
	}
	return buffer;
}

void init_counter(struct counter_state *state, const unsigned char iv[8]) {
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);
	memset(state->ivec + 8, 0, 8);
	memcpy(state->ivec, iv, 8);
}

int serverProxy(int port, int dest_port, char* destination_host, unsigned const char *key){
	int socket_desc , client_sock , c;
	struct sockaddr_in server , ssh_server, client;

	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1)
	{
			printf("Could not create socket");
	}
	fprintf(stderr,"Socket created");

	struct hostent *service_host;

	if ((service_host=gethostbyname(destination_host)) == 0)
	{
	  fprintf(stderr, "Error in getting host by name!\n");
	  exit(EXIT_FAILURE);
	}
	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( port );

	ssh_server.sin_family = AF_INET;
	ssh_server.sin_port = htons(dest_port);
	ssh_server.sin_addr.s_addr = ((struct in_addr *)(service_host->h_addr))->s_addr;

	//Bind
	if(bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
	{
			//print the error message
			perror("bind failed. Error");
			return 1;
	}
	puts("\nbinding done");

	//Listen
	listen(socket_desc , 3);

	//Accept and incoming connection
	puts("Waiting for incoming connections...");

  c = sizeof(struct sockaddr_in);

  while(1){
	 unsigned char buffer[BUF_SIZE];
   int ssh_fd, n;
   bool ssh_done = false;
	 bool iv_received=false;

	//accept connection from an incoming client
	client_sock = (int)accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
	if (client_sock < 0)
	{
			perror("accept failed");
			return 1;
	}
	puts("Connection accepted");

  ssh_fd = socket(AF_INET, SOCK_STREAM, 0);


	if (connect(ssh_fd , (struct sockaddr *)&ssh_server , sizeof(ssh_server)) < 0)
	{
			perror("ssh connection failed. Error");
			return 1;
	}
	else {
	 printf("Connection to ssh established!\n");
  }


	int flags = fcntl(client_sock , F_GETFL);
	if (flags == -1) {
		printf("read sock 1 flag error!\n");
		printf("Closing connection\n");
		close(client_sock );
		close(ssh_fd);
	}
	fcntl(client_sock, F_SETFL, flags | O_NONBLOCK);

	flags = fcntl(ssh_fd, F_GETFL);
	if (flags == -1) {
		printf("read ssh_fd flag error!\n");
		close(client_sock );
		close(ssh_fd);
	}
	fcntl(ssh_fd, F_SETFL, flags | O_NONBLOCK);

	struct counter_state state;
	AES_KEY aes_key;
	unsigned char iv[8];
	memset(buffer, 0,BUF_SIZE);

	if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
		fprintf(stderr, "Set encryption key error!\n");
		exit(1);
	}

while(1){

	while( (n = read(client_sock , buffer , BUF_SIZE)) > 0 )
	{
			if(!iv_received){
				if (n < 8) {
					printf("Packet length smaller than 8!\n");
					close(client_sock);
					close(ssh_fd);
				}
				memcpy(iv, buffer, 8);
				init_counter(&state, iv);
				iv_received=true;
			}
			else{
				unsigned char decryption[n];
				AES_ctr128_encrypt(buffer, decryption, n, &aes_key, state.ivec, state.ecount, &state.num);
				write(ssh_fd, decryption, n);
				memset(decryption, 0,n);
			}

			memset(buffer, 0,BUF_SIZE);
			if (n < BUF_SIZE)
				break;
	}

	while((n = read(ssh_fd , buffer , BUF_SIZE)) >= 0)
	{
			if (n > 0) {
				//char *tmp = (char*)malloc(n);
				unsigned char encryption[n];
				AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec, state.ecount, &state.num);
				//memcpy(tmp, encryption, n);
				write(client_sock, encryption, n);
				memset(buffer, 0,BUF_SIZE);
				memset(encryption, 0,n);
				//free(tmp);
			}
			if (ssh_done == false && n == 0)
			    ssh_done = true;
			if (n< BUF_SIZE)
				break;
	}
	if (ssh_done)
			break;
 }
}
	return 0;
}

int clientProxy(int port, char* destination_host, unsigned const char *key){
	int sock;
	int n;
	struct sockaddr_in server;
	unsigned char buffer[BUF_SIZE];
	struct hostent *dest_host;

	if ((dest_host=gethostbyname(destination_host)) == 0) {
	  fprintf(stderr, "Error in getting host by name!\n");
	  exit(EXIT_FAILURE);
	}
	//Create socket
	sock = socket(AF_INET , SOCK_STREAM , 0);
	if (sock == -1)
	{
			printf("Could not create socket");
	}
	puts("Socket created");

	server.sin_addr.s_addr = ((struct in_addr *)(dest_host->h_addr))->s_addr;
	server.sin_family = AF_INET;
	server.sin_port = htons( port);

	//Connect to remote server
	if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
	{
			perror("connect failed. Error");
			return 1;
	}

	fprintf(stderr,"Connected\n");

	fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
	fcntl(sock, F_SETFL, O_NONBLOCK);

	struct counter_state state;
	unsigned char iv[8];
	AES_KEY aes_key;

	if(!RAND_bytes(iv, 8)) {
		fprintf(stderr, "Error generating random bytes.\n");
		exit(1);
	}
	init_counter(&state, iv);

	if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
		fprintf(stderr, "Set encryption key error!\n");
		exit(1);
	}

	if( send(sock , iv , 8 , 0) < 0)
 {
		puts("Sending iv failed");
		return 1;
 }
	//keep communicating with server
	while(1)
	{
		 while((n=read(STDIN_FILENO, buffer, BUF_SIZE))>0){
			 unsigned char encryption[n];
			 AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec, state.ecount, &state.num);
			 write(sock, encryption, n);
			 memset(buffer,0,BUF_SIZE);
			 memset(encryption, 0,n);
			 if (n < BUF_SIZE)
				break;
		 }
     while((n = read(sock , buffer, BUF_SIZE)) > 0 ){
			 unsigned char decryption[n];
			 AES_ctr128_encrypt(buffer, decryption, n, &aes_key, state.ivec, state.ecount, &state.num);
			 write(STDOUT_FILENO, decryption, n);
			 memset(buffer, 0,BUF_SIZE);
			 memset(decryption, 0,n);
			 if (n  < BUF_SIZE)
				 break;
		 }
	}
	close(sock);
	return 0;
}


int main(int argc, char *argv[]) {

  int option=0;
	char* listenPort=NULL;
	bool proxy_server = false;
	char *mykey = NULL;
	char *destination_host = NULL;
  char *destination_port = NULL;
	unsigned const char *my_key=NULL;


// process input arguments
while ((option = getopt(argc, argv, "l:k:")) != -1) {
		switch(option) {
			case 'l':
				listenPort = optarg;
				proxy_server = true;
				break;
			case 'k':
				mykey = optarg;
				break;
			case '?':
				if (optopt == 'l') {
					fprintf(stderr, "Option -%c requires an argument.\n", optopt);
					return 0;
				}
				 else if (optopt == 'k') {
					fprintf(stderr, "Option -%c requires an argument.\n", optopt);
					return 0;
				}
				else {
					fprintf(stderr, "Unknown option character\n");
					return 0;
				}
			default:
				return 0;
		}
	}

if (optind == argc - 2) {
	destination_host = argv[optind];
	destination_port = argv[optind+1];
}
else {
	fprintf(stderr, "destination and port arguments not provided.\n");
	return 0;
}

if (mykey == NULL) {
	fprintf(stderr, "Key File was not provided\n");
	return 0;
}
fprintf(stderr, "\n\tInitializing pbproxy using following parameters:\nserver mode: %s\nlistening port: %s\nkey file: %s\ndestination host: %s\ndestination port: %s\n\n\n", proxy_server ? "true" : "false", listenPort, mykey, destination_host, destination_port);

my_key = (unsigned const char *)read_file((const char*)mykey);

if (!my_key) {
	fprintf(stderr, "error in reading file!\n");
	return 0;
}

struct sockaddr_in servaddr, sshaddr;
bzero(&servaddr, sizeof(servaddr));
bzero(&sshaddr, sizeof(sshaddr));

if(proxy_server){
	  serverProxy(atoi(listenPort), atoi(destination_port),destination_host, my_key);
}
else {
		clientProxy(atoi(destination_port),destination_host, my_key);
}

}
