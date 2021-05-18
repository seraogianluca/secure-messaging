#include <iostream>
#include <string>
#include "symbols.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

using namespace std;

class Crypto {
    private:
        // Controllare che non restino salvate da qualche parte altrimenti non è sicura!!
        unsigned char *session_key;
        unsigned char *iv;

        int generateIV();
    public:
        Crypto(unsigned char *sk) {
            session_key = new unsigned char[KEY_SIZE];
            for(int i = 0; i < KEY_SIZE; i++) {
                session_key[i] = sk[i];
            }
        }

        ~Crypto() {
            delete session_key;
        }

        //EVP_PKEY* readPrivateKey(string pwd);
        string generateNonce();
        unsigned char* getIV();

        // Authenticated encryption
        int encryptMessage(unsigned char *msg, int msg_len, unsigned char *ciphr_msg, unsigned char *tag);
        int decryptMessage(unsigned char *ciphr_msg, int ciphr_len, unsigned char *iv_src, unsigned char* tag, unsigned char *msg);
};