#include "include/server.h"

int main(){
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    unsigned char cert_buff[2048] = {0};
    string hello = "Hello from server";
    Crypto c((unsigned char*)"1234567890123456");
    X509* cert = c.loadCertificate();
    X509_NAME* sub_name = X509_get_subject_name(cert);
    char* tmpstr = X509_NAME_oneline(sub_name,NULL,0);
    cout<<"Subject name: "<<tmpstr<<endl;
    free(sub_name);
    if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        cerr << "Socket failed" << endl;
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if(bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        cerr << "Bind failed" << endl;
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        cerr << "Listen..." << endl;
        exit(EXIT_FAILURE);
    }

    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {
        cerr << "Accept..." << endl;
        exit(EXIT_FAILURE);
    }
    try{
        valread = read( new_socket , buffer, 1024);
        printf("%s\n",buffer );
        send(new_socket , hello.c_str() , hello.length() , 0 );
        printf("Hello message sent\n");
        int len = c.sendCertificate(new_socket,cert,cert_buff);
        send(new_socket,cert_buff,len,0);
        printf("Certificate sended\n");
    }catch(const char *msg) {
        cerr << msg << endl;
    }
    return 0;
}