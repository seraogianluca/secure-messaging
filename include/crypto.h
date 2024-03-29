#include <iostream>
#include <string>
#include <array>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "symbols.h"

using namespace std;

struct session {
    unsigned char *session_key;
    unsigned char iv[IV_SIZE];
    uint16_t received;
    uint16_t counter;
    
    session(){}

    session(unsigned char *sk){
        session_key = new (nothrow) unsigned char[DIGEST_LEN];
        if(!session_key){
            throw runtime_error("Buffer not initialized.");
        }
        memcpy(session_key, sk, DIGEST_LEN);
        counter = 0;
        received = 0;
    }

    void generateIV() {
        if(RAND_poll() != 1)
            throw runtime_error("An error occurred in RAND_poll."); 
        if(RAND_bytes(iv, IV_SIZE) != 1)
            throw runtime_error("An error occurred in RAND_bytes.");
        increment(counter);
    }

    void increment(uint16_t &value){
        if(value == UINT16_MAX){
            value = 0;
        } else {
            value++;
        }
    }

    void getCounter(unsigned char *buffer){
        unsigned char sizeArray[2];
        sizeArray[0] = counter & 0xFF; //low part
        sizeArray[1] = counter >> 8;   //higher part
        memcpy(buffer, sizeArray, 2);
    }

    bool verifyFreshness(unsigned char *counterReceived){
        uint16_t tmp = received;
        uint16_t cr = counterReceived[0] | uint16_t(counterReceived[1]) << 8;
        increment(tmp);
        if(tmp == cr){
            increment(received);
            return true;
        }
        return false;
    }

    void removeKey() {
        for(int i = 0; i < DIGEST_LEN; i++) {
            session_key[i] = 0x00;
        }
    }
};

class Crypto {
    private:
        array<session, MAX_CLIENTS> sessions;
        unsigned int currentSession = 0;

        // Diffie-Hellman
        void buildParameters(EVP_PKEY *&dh_params);
        // Hash
        void computeHash(unsigned char *msg, unsigned int msg_size, unsigned char *digest);
        // Certificates
        void loadCRL(X509_CRL*& crl);

    public:
        Crypto() {}

        void insertKey(unsigned char *key, unsigned int pos);
        void removeKey(unsigned int pos);
        void setSessionKey(unsigned int key);
        void generateNonce(unsigned char* nonce);

        void readPrivateKey(string usr, string pwd, EVP_PKEY *&prvKey);
        void readPrivateKey(EVP_PKEY *&prvKey);
        void readPublicKey(string user, EVP_PKEY *&pubKey);

        // Authenticated encryption
        unsigned int encryptMessage(unsigned char *msg, unsigned int msg_len, unsigned char *buffer);
        unsigned int decryptMessage(unsigned char *msg, unsigned int msg_len, unsigned char *buffer);
       
        // Certificates
        void loadCertificate(X509*& cert, string path);
        unsigned int serializeCertificate(X509* cert, unsigned char* cert_buf);
        void deserializeCertificate(int cert_len,unsigned char* cert_buff, X509*& buff);
        bool verifyCertificate(X509* cert_to_verify);

        // Public Key handling
        unsigned int serializePublicKey(EVP_PKEY *pub_key, unsigned char *pubkey_buf);
        void deserializePublicKey(unsigned char *pubkey_buf, unsigned int pubkey_size, EVP_PKEY *&pubkey);
        void getPublicKeyFromCertificate(X509 *cert, EVP_PKEY *&pubkey);

        // Diffie-Hellmann
        void keyGeneration(EVP_PKEY *&my_prvkey);
        void secretDerivation(EVP_PKEY *my_pubkey, EVP_PKEY *peer_pubkey, unsigned char *buffer);

        // Digital Signature
        unsigned int sign(unsigned char *message, unsigned int messageLen, unsigned char *buffer, EVP_PKEY *prvKey);
        bool verifySignature(unsigned char *signature, unsigned int signLen, unsigned char *message, unsigned int messageLen, EVP_PKEY *pubKey);
};