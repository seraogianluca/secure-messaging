#include "include/crypto.h"

void Crypto::insertKey(unsigned char *key, unsigned int pos) {
    session s(key);
    sessions.insert(sessions.begin() + pos, s);
}

void Crypto::removeKey(unsigned int pos) {
    sessions.erase(sessions.begin() + pos, sessions.begin() + pos + 1);
}

void Crypto::setSessionKey(unsigned int pos) {
    currentSession = pos;
}

void Crypto::generateNonce(unsigned char* nonce) {
    if(RAND_poll() != 1)
        throw runtime_error("An error occurred in RAND_poll."); 
    if(RAND_bytes(nonce, NONCE_SIZE) != 1)
        throw runtime_error("An error occurred in RAND_bytes.");
}

void Crypto::readPrivateKey(EVP_PKEY *&prvKey) {
    FILE* file;
    file = fopen("./keys/server_prv_key.pem", "r");
    if(!file)
        throw runtime_error("An error occurred, the file doesn't exist.");
    prvKey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    if(!prvKey){
        fclose(file);
        throw runtime_error("An error occurred while reading the private key.");
    }

    fclose(file);
}

void Crypto::readPrivateKey(string usr, string pwd, EVP_PKEY *& prvKey) {
    FILE* file;
    string path;
    path = "./keys/" + usr + "_prvkey.pem";
    file = fopen(path.c_str(), "r");
    if(!file)
        throw runtime_error("An error occurred, the file doesn't exist.");
    prvKey = PEM_read_PrivateKey(file, NULL, NULL, (char*)pwd.c_str());
    if(!prvKey){
        fclose(file);
        throw runtime_error("An error occurred while reading the private key.");
    }

    fclose(file);
}

void Crypto::readPublicKey(string user, EVP_PKEY *&pubKey) {
    //QUESTION: necessario controllo su user tramite white/black list??
    FILE* file;
    string path = "./keys/" + user + "_pubkey.pem";
    file = fopen(path.c_str(), "r");
    if(!file)
        throw runtime_error("An error occurred, the file doesn't exist.");
    pubKey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if(!pubKey){
        fclose(file);
        throw runtime_error("An error occurred while reading the private key.");
    }

    fclose(file);
}

void Crypto::getPublicKeyFromCertificate(X509 *cert, EVP_PKEY *&pubkey){
    pubkey = X509_get_pubkey(cert);
    if(!pubkey)
        throw runtime_error("An error occurred while getting the key from the certificate.");
}

unsigned int Crypto::encryptMessage(unsigned char *msg, unsigned int msg_len, unsigned char *buffer) {
    unsigned char *ciphertext;
    unsigned char bufferCounter[sizeof(uint16_t)];
    unsigned char tag[TAG_SIZE];
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned int finalSize = 0;
    unsigned int start = 0;
    int len = 0;
    int ciphr_len = 0;

    if( msg_len > (UINT_MAX - 2*TAG_SIZE + IV_SIZE + sizeof(uint16_t)) )
        throw runtime_error("Message too big.");

    finalSize = msg_len + 2*TAG_SIZE + IV_SIZE + sizeof(uint16_t);

    if(finalSize > MAX_MESSAGE_SIZE)
        throw runtime_error("Message too big.");

    ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
        throw runtime_error("An error occurred while creating the context."); 
    
    ciphertext = new (nothrow) unsigned char[msg_len + TAG_SIZE];

    if(!ciphertext){
        throw runtime_error("An error occurred initilizing the buffer");
    }

    try {
        session& s = sessions.at(currentSession);
        s.generateIV();

        if(EVP_EncryptInit(ctx, AUTH_ENCR, s.session_key, s.iv) != 1)
            throw runtime_error("An error occurred while initializing the context.");
            
        // AAD: Insert the counter
        if(EVP_EncryptUpdate(ctx, NULL, &len, s.iv, IV_SIZE) != 1)
            throw runtime_error("An error occurred while encrypting the message.");

        s.getCounter(bufferCounter);
        if(EVP_EncryptUpdate(ctx, NULL, &len, bufferCounter, sizeof(uint16_t)) != 1)
            throw runtime_error("An error occurred while encrypting the message.");
            
        if(EVP_EncryptUpdate(ctx, ciphertext, &len, msg, msg_len) != 1)
            throw runtime_error("An error occurred while encrypting the message.");
        ciphr_len = len;

        if(EVP_EncryptFinal(ctx, ciphertext + len, &len) != 1)
            throw runtime_error("An error occurred while finalizing the ciphertext.");
        ciphr_len += len;

        //Get the tag
        if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag) != 1)
            throw runtime_error("An error occurred while getting the tag.");
        
        if(ciphr_len < 0)
            throw runtime_error("An error occurred, negative ciphertext length.");
        
        if(ciphr_len > UINT_MAX - IV_SIZE - TAG_SIZE - sizeof(uint16_t))
            throw runtime_error("An error occurred, ciphertext length too big.");
        
        memcpy(buffer+start, s.iv, IV_SIZE);
        start += IV_SIZE;
        memcpy(buffer+start, bufferCounter, sizeof(uint16_t));
        start += sizeof(uint16_t);
        memcpy(buffer+start, ciphertext, ciphr_len);
        start += ciphr_len;
        memcpy(buffer+start, tag, TAG_SIZE);
        start += TAG_SIZE;
    } catch(const exception& e) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return start;
}

unsigned int Crypto::decryptMessage(unsigned char *msg, unsigned int msg_len, unsigned char *buffer) {
    unsigned char recv_iv[IV_SIZE];
    unsigned char recv_tag[TAG_SIZE];
    unsigned char bufferCounter[sizeof(uint16_t)];
    unsigned char *ciphr_msg;
    unsigned char *tempBuffer;
    EVP_CIPHER_CTX *ctx;
    unsigned int ciphr_len = 0;
    int ret = 0;
    int len = 0;
    int pl_len = 0;


    if (msg_len < (IV_SIZE + TAG_SIZE))
        throw runtime_error("Message length not valid.");
    
    if(msg_len > MAX_MESSAGE_SIZE)
        throw runtime_error("Message too big.");

    ciphr_len = msg_len - IV_SIZE - TAG_SIZE - sizeof(uint16_t);
    ciphr_msg = new (nothrow) unsigned char[ciphr_len];

    if(!ciphr_msg)
        throw runtime_error("An error occurred while allocating the array for the ciphertext.");

    tempBuffer = new (nothrow) unsigned char[ciphr_len];
    if(!tempBuffer)
        throw runtime_error("An error occurred while allocating the temporary array for the ciphertext.");

    ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        delete[] ciphr_msg;
        throw runtime_error("An error occurred while creating the context.");
    } 

    try {
        memcpy(recv_iv, msg, IV_SIZE);
        memcpy(bufferCounter, msg + IV_SIZE, sizeof(uint16_t));
        memcpy(ciphr_msg, msg + IV_SIZE + sizeof(uint16_t), ciphr_len);
        memcpy(recv_tag, msg + msg_len - TAG_SIZE, TAG_SIZE);
        session& s = sessions.at(currentSession);

        if(!s.verifyFreshness(bufferCounter)){
            throw runtime_error("Freshness not confirmed.");
        }

        if(!EVP_DecryptInit(ctx, AUTH_ENCR, s.session_key, recv_iv))
            throw runtime_error("An error occurred while initializing the context.");
        
        if(!EVP_DecryptUpdate(ctx, NULL, &len, recv_iv, IV_SIZE))
            throw runtime_error("An error occurred while getting AAD header.");
        
        if(!EVP_DecryptUpdate(ctx, NULL, &len, bufferCounter, sizeof(uint16_t)))
            throw runtime_error("An error occurred while getting AAD header.");
            
        if(!EVP_DecryptUpdate(ctx, tempBuffer, &len, ciphr_msg, ciphr_len))
            throw runtime_error("An error occurred while decrypting the message");
        pl_len = len;
        
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, recv_tag))
            throw runtime_error("An error occurred while setting the expected tag.");
        
        ret = EVP_DecryptFinal(ctx, tempBuffer + len, &len);

        memcpy(buffer, tempBuffer, pl_len);
    } catch(const exception& e) {
        delete[] ciphr_msg;
        delete[] tempBuffer;
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }

    delete[] ciphr_msg;
    delete[] tempBuffer;
    EVP_CIPHER_CTX_free(ctx);
    
    if(ret > 0){
        pl_len += len;
    } else
        throw runtime_error("An error occurred while decrypting the message.");
    
    if (pl_len < 0 || pl_len > UINT_MAX) 
        throw runtime_error("An error occurred while decrypting the message.");

    return pl_len;
}

void Crypto::loadCertificate(X509*& cert, string path){
    string path_str = "./cert/"+path+".pem";
    FILE *file = fopen(path_str.c_str(),"r");
    if(!file)
        throw runtime_error("An error occurred while opening the file.");
    cert = PEM_read_X509(file,NULL,NULL,NULL);
    if(!cert){
        fclose(file);
        throw runtime_error("An error occurred while reading the pem certificate.");
    }

    fclose(file);
}

unsigned int Crypto::serializeCertificate(X509* cert, unsigned char* cert_buf){
    int cert_size = i2d_X509(cert,&cert_buf);
    if(cert_size < 0)
        throw runtime_error("An error occurred during the writing of the certificate.");
    return cert_size;
}

void Crypto::deserializeCertificate(int cert_len,unsigned char* cert_buff, X509*& buff){
    buff = d2i_X509(NULL,(const unsigned char**)&cert_buff,cert_len);
    if(!buff)
        throw runtime_error("An error occurred during the reading of the certificate.");
}

void Crypto::loadCRL(X509_CRL*& crl){
    FILE* file = fopen("./cert/crl.pem", "r");

    if(!file)
        throw runtime_error("An error occurred opening crl.pem.");

    crl = PEM_read_X509_CRL(file, NULL, NULL, NULL); 

    if(!crl) { 
        fclose(file);
        throw runtime_error("An error occurred reading the crl from file");
    }

    fclose(file);
}

bool Crypto::verifyCertificate(X509* cert_to_verify) {
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509* ca_cert;
    X509_STORE* store;
    X509_CRL* crl;

    loadCertificate(ca_cert,CA_CERT_PATH);
    loadCRL(crl);

    store = X509_STORE_new();
    if(!store)
        throw runtime_error("An error occured during the allocation of the store");
    
    try {
        if(X509_STORE_add_cert(store, ca_cert)<1)
            throw runtime_error("An error occurred adding the certification to the store");
    
        if(X509_STORE_add_crl(store, crl)<1)
            throw runtime_error("An error occurred adding the crl to the store");
        
        if(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK)<1)
            throw runtime_error("An error occurred adding the flags to the store");
        
        if(X509_STORE_CTX_init(ctx, store, cert_to_verify, NULL)==0)
            throw runtime_error("An error occurred during the initialization of the context");
    } catch(const exception& e) {
        X509_STORE_free(store);
        throw;
    }

    if(X509_verify_cert(ctx) != 1) { 
        X509_STORE_free(store);
        X509_STORE_CTX_free(ctx);
        return false;
    }

    X509_STORE_free(store);
    X509_STORE_CTX_free(ctx);
    return true;
}

unsigned int Crypto::serializePublicKey(EVP_PKEY *pub_key, unsigned char *pubkey_buf){
    BIO *mbio;
    unsigned char *buffer;
    long pubkey_size; 

    mbio = BIO_new(BIO_s_mem());
    if(!mbio)
        throw runtime_error("An error occurred during the creation of the bio.");

    if(PEM_write_bio_PUBKEY(mbio,pub_key) != 1){
        BIO_free(mbio);
        throw runtime_error("An error occurred during the writing of the public key into the bio.");
    }

    pubkey_size = BIO_get_mem_data(mbio, &buffer);
    memcpy(pubkey_buf, buffer, pubkey_size);

    if(pubkey_size < 0 || pubkey_size > UINT_MAX) {
        BIO_free(mbio);
        throw runtime_error("An error occurred during the reading of the public key.");
    }

    BIO_free(mbio);

    return pubkey_size;
}

void Crypto::deserializePublicKey(unsigned char* pubkey_buf, unsigned int pubkey_size, EVP_PKEY *&pubkey){
    BIO *mbio;

    mbio = BIO_new(BIO_s_mem());

    if(!mbio)
        throw runtime_error("An error occurred during the creation of the bio.");

    if(BIO_write(mbio,pubkey_buf,pubkey_size) <= 0)
        throw runtime_error("An error occurred during the writing of the bio.");

    pubkey = PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);

    if(!pubkey){
        BIO_free(mbio);
        throw runtime_error("An error occurred during the reading of the public key from the bio.");
    }

    BIO_free(mbio);
}

void Crypto::computeHash(unsigned char *msg, unsigned int msg_size, unsigned char *digest) {
    unsigned int len;
    EVP_MD_CTX *ctx;

    ctx = EVP_MD_CTX_new();
    if(!ctx)
        throw runtime_error("An error occurred while creating the context.");

    try {
        if(EVP_DigestInit(ctx, HASH) < 1)
            throw runtime_error("An error occurred during the initialization of the digest.");

        if(EVP_DigestUpdate(ctx, msg, msg_size) < 1)
            throw runtime_error("An error occurred during the creation of the digest.");

        if(EVP_DigestFinal(ctx, digest, &len) < 1)
            throw runtime_error("An error occurred during the conclusion of the digest.");
    } catch(const exception& e) {
        EVP_MD_CTX_free(ctx);
        throw;
    }

    EVP_MD_CTX_free(ctx);
}

void Crypto::buildParameters(EVP_PKEY *&dh_params) {
    DH *temp;
    dh_params = EVP_PKEY_new();

    if(!dh_params)
        throw runtime_error("An error occurred during the allocation of parameters.");

    temp = DH_get_2048_224();

    if(EVP_PKEY_set1_DH(dh_params,temp) == 0){
        DH_free(temp);
        throw runtime_error("An error occurred during the generation of parameters.");
    }

    DH_free(temp);
}

void Crypto::keyGeneration(EVP_PKEY *&my_prvkey){
    EVP_PKEY *dh_params = NULL;
    EVP_PKEY_CTX *ctx;

    buildParameters(dh_params);

    ctx = EVP_PKEY_CTX_new(dh_params,NULL);
    if(!ctx)
        throw runtime_error("An error occurred during the creation of the context");

    try
    {
        if(EVP_PKEY_keygen_init(ctx) < 1) 
            throw runtime_error("An error occurred during the intialization of the context");

        if(EVP_PKEY_keygen(ctx, &my_prvkey) < 1)
            throw runtime_error("An error occurred during the intialization of the context");
    } catch(const exception& e) {
        EVP_PKEY_CTX_free(ctx);
        throw;
    }
    EVP_PKEY_CTX_free(ctx);
}

void Crypto::secretDerivation(EVP_PKEY *my_prvkey, EVP_PKEY *peer_pubkey, unsigned char *buffer) {
    EVP_PKEY_CTX *ctx_drv;
    size_t secretlen;
    unsigned char *secret;

    if(!peer_pubkey)
        throw runtime_error("An error occurred reading the public key.");

    ctx_drv = EVP_PKEY_CTX_new(my_prvkey,NULL);
    if(!ctx_drv)
        throw runtime_error("An error occurred during the creation of the context.");

    if(EVP_PKEY_derive_init(ctx_drv) < 1){
        EVP_PKEY_CTX_free(ctx_drv);
        throw runtime_error("An error occurred during the intialization of the context.");
    } 

    if(EVP_PKEY_derive_set_peer(ctx_drv, peer_pubkey) < 1){
        EVP_PKEY_CTX_free(ctx_drv);
        throw runtime_error("An error occurred setting the peer's public key.");
    }  
     
    if(EVP_PKEY_derive(ctx_drv, NULL, &secretlen) < 1){
        EVP_PKEY_CTX_free(ctx_drv);
        throw runtime_error("An error occurred retrieving the secret length.");
    }

    secret = (unsigned char*)OPENSSL_malloc(secretlen);
    if(!secret) {
        EVP_PKEY_CTX_free(ctx_drv);
        throw runtime_error("An error occurred allocating the unsigned char array.");
    }

    if(EVP_PKEY_derive(ctx_drv, secret, &secretlen) < 1){
        EVP_PKEY_CTX_free(ctx_drv);
        OPENSSL_free(secret);
        throw runtime_error("An error occurred during the derivation of the secret.");
    }

    EVP_PKEY_CTX_free(ctx_drv);
    computeHash(secret, secretlen, buffer);
    OPENSSL_free(secret);
}

unsigned int Crypto::sign(unsigned char *message, unsigned int messageLen, unsigned char *buffer, EVP_PKEY *prvKey) {
    unsigned char *signature; 
    unsigned int signLen;
    signature = new(nothrow) unsigned char[EVP_PKEY_size(prvKey)];
    if(!signature) {
        throw runtime_error("Buffer not allocated correctly");
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw runtime_error("Context not initialized");
    }
    try {
        if(EVP_SignInit(ctx, EVP_sha256()) != 1) {
            throw runtime_error("Error inizializing the sign");
        }
        if(EVP_SignUpdate(ctx, message, messageLen) != 1) {
            throw runtime_error("Error updating the sign");
        }
        if(EVP_SignFinal(ctx, signature, &signLen, prvKey) != 1){
            throw runtime_error("Error finalizing the sign");
        }
        memcpy(buffer, signature, signLen);
        delete[] signature;
        EVP_MD_CTX_free(ctx);
    } catch(const exception& e) {
        delete[] signature;
        EVP_MD_CTX_free(ctx);
        throw;
    }
    return signLen;
}

bool Crypto::verifySignature(unsigned char *signature, unsigned int signLen, unsigned char *message, unsigned int messageLen, EVP_PKEY *pubKey) {
    int ret;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw runtime_error("Context not initialized");
    }
    try {
        if(EVP_VerifyInit(ctx, EVP_sha256()) != 1){
            throw runtime_error("Error initializing the signature verification");
        }
        if(EVP_VerifyUpdate(ctx, message, messageLen) != 1) {
            throw runtime_error("Error updating the signature verification");
        }
        ret = EVP_VerifyFinal(ctx, signature, signLen, pubKey); 
        EVP_MD_CTX_free(ctx);
        if(ret != 1) { 
            return false;
        }
    } catch(const exception& e) {
        EVP_MD_CTX_free(ctx);
        throw;
    }
    return true;
}