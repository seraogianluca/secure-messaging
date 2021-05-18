#include "include/client.h"

int Client::login(string pwd) {
    // Generate nonce

    Crypto crypto = new Crypto(); // Refactor
    unsigned char* nonce_client = crypto.generateNonce();

    // public key (stored in server)
    // private key (protected with pwd)
    // authentication protocol with server ->

    // retrieve privK from PEM with PWD
    // encrypt server certificate request with privK
    // client send certificate request to server
    // receive certificate
    // verify certificate

    // receive authentication request encrypted with pubK
    // send response

    // session key establishment

    // client sends client_hello
    // server sends server_hello
    // server sends certificate
    // client verifies certificate

    // client sends certificate
    // server verifies certificate    
}