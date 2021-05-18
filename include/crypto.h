#include <iostream>
#include <string>
#include "symbols.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

using namespace std;

class Crypto {
    private:

    public:
        Crypto() {};
        //EVP_PKEY* readPrivateKey(string pwd);
        unsigned char* generateNonce();

};