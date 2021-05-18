#include "include/crypto.h"

/*
EVP_PKEY* Crypto::readPrivateKey(string pwd) {
    EVP_PKEY* prvKey;
    FILE* file;
    file = fopen("prvkey.pem", "r");
    if(!file) {
        cerr << "Error: file does not exists";
        return NULL;
    }
    prvKey = PEM_read_PrivateKey(file, NULL, NULL, (char*)pwd.c_str());
    fclose(file);
    if(!prvKey){ 
        cerr << "Error: PEM_read_PRVKEY returned NULL\n";
        return NULL;
    }
    return prvKey;
}
*/

unsigned char* Crypto::generateNonce(){ 
    RAND_poll();
    unsigned char


    return NULL;
}