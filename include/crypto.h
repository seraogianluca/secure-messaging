#include <iostream>
#include <string>
#include <string.h>
#include "symbols.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>

using namespace std;
//TODO: mettere il throw runtime_exception
//TODO: mettere una funzione per stampare gli errori
class Crypto {
    private:
        // Controllare che non restino salvate da qualche parte altrimenti non è sicura!!
        unsigned char *session_key;
        unsigned char *iv;

        void generateIV();

        // Diffie-Hellman
        void buildParameters(EVP_PKEY *&dh_params);
    public:
        Crypto(unsigned char *sk);
        ~Crypto();

        void setSessionKey(unsigned char *secret);
        string generateNonce();
        unsigned char* getIV();

        EVP_PKEY* readPrivateKey(string pwd);
        EVP_PKEY* readPublicKey(string user);

        // Authenticated encryption
        int encryptMessage(unsigned char *msg, int msg_len, unsigned char *ciphr_msg, unsigned char *tag);
        int decryptMessage(unsigned char *ciphr_msg, int ciphr_len, unsigned char *iv_src, unsigned char* tag, unsigned char *msg);
       
        // Certificates
        X509* loadCertificate();
        int sendCertificate(X509* cert, unsigned char* cert_buf);
        X509* receiveCertificate(int cert_len,unsigned char* cert_buff);
        X509_CRL* loadCRL();
        bool verifyCertificate(unsigned char* cert_buff, int cert_len);

        // Public Key handling
        int serializePublicKey(EVP_PKEY *prv_key, unsigned char *pubkey_buf);
        void deserializePublicKey(unsigned char *pubkey_buf, unsigned int pubkey_size, EVP_PKEY *&pubkey);

        // Hash
        //TODO: may be private
        void computeHash(unsigned char *msg, unsigned int msg_size, unsigned char *digest);

        //Diffie-Hellmann
        void keyGeneration(EVP_PKEY *&my_prvkey);
        void secretDerivation(EVP_PKEY *my_pubkey, EVP_PKEY *peer_pubkey, unsigned char *buffer);
};