#include "include/client.h"

int main(){
	int sock = 0, valread;
	struct sockaddr_in serv_addr;
    string hello = "Hello from client";
    char buffer[1024] = {0};
    unsigned char cert_buff[2048] = {0};
    Crypto c((unsigned char*)"1234567890123456");
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Socket creation error \n");
		return -1;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);
	
	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)
	{
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		printf("\nConnection Failed \n");
		return -1;
	}
    try{
        send(sock , hello.c_str() , hello.length() , 0 );
        printf("Hello message sent\n");
        valread = read( sock , buffer, 1024);
        printf("%s\n",buffer );
        int len = recv(sock,cert_buff,2048,MSG_WAITALL);
        X509* cert = c.receiveCertificate(sock,len,cert_buff);
        X509_NAME* sub_name = X509_get_subject_name(cert);
        char* tmpstr = X509_NAME_oneline(sub_name,NULL,0);
        cout<<"Subject name: "<<tmpstr<<endl;
        free(sub_name);
    }catch(const char *msg) {
        cerr << msg << endl;
    }
	return 0;
}
