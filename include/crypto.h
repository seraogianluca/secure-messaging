#include <iostream>
#include <string>
#include <vector>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "symbols.h"

using namespace std;
//TODO: mettere una funzione per stampare gli errori
class Crypto {
    private:
        vector< vector<unsigned char> > keys;
        unsigned char *session_key;
        unsigned char *iv;

        void generateIV();

        // Diffie-Hellman
        void buildParameters(EVP_PKEY *&dh_params);
    public:
        Crypto(int num_keys);
        ~Crypto();

        void insertKey(unsigned char *key, unsigned int pos);
        void setSessionKey(unsigned int key);
        void generateNonce(unsigned char* nonce);

        void readPrivateKey(string usr, string pwd, EVP_PKEY *&prvKey);
        void readPrivateKey(EVP_PKEY *&prvKey);
        void readPublicKey(string user, EVP_PKEY *&pubKey);

        // Authenticated encryption
        int encryptMessage(unsigned char *msg, unsigned int msg_len, unsigned char *buffer);
        int decryptMessage(unsigned char *msg, unsigned int msg_len, unsigned char *buffer);
       
        // Certificates
        void loadCertificate(X509*& cert, string path);
        int serializeCertificate(X509* cert, unsigned char* cert_buf);
        void deserializeCertificate(int cert_len,unsigned char* cert_buff, X509*& buff);
        void loadCRL(X509_CRL*& crl);
        bool verifyCertificate(X509* cert_to_verify);

        // Public Key handling
        int serializePublicKey(EVP_PKEY *pub_key, unsigned char *pubkey_buf);
        void deserializePublicKey(unsigned char *pubkey_buf, unsigned int pubkey_size, EVP_PKEY *&pubkey);
        int publicKeyEncryption(unsigned char *msg, unsigned int msg_len, unsigned char *buff, EVP_PKEY *pubkey);
        int publicKeyDecryption(unsigned char *msg, unsigned int msg_len, unsigned char *buff, EVP_PKEY *prvkey);
        void getPublicKeyFromCertificate(X509 *cert, EVP_PKEY *&pubkey);
        
        // Hash
        //TODO: may be private
        void computeHash(unsigned char *msg, unsigned int msg_size, unsigned char *digest);

        //Diffie-Hellmann
        void keyGeneration(EVP_PKEY *&my_prvkey);
        void secretDerivation(EVP_PKEY *my_pubkey, EVP_PKEY *peer_pubkey, unsigned char *buffer);
};