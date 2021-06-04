#include "include/crypto.h"

Crypto::Crypto(int num_keys) {
    keys = NULL;
    session_key = NULL;
    iv = NULL;
    max_keys = 0;

    try {
        iv = new unsigned char[IV_SIZE];
        for(int i = 0; i < IV_SIZE; i++) {
            iv[i] = 0;
        }

        session_key = new unsigned char[DIGEST_LEN];
        for(int i = 0; i < DIGEST_LEN; i++) {
            session_key[i] = 0;
        }

        keys = new unsigned char*[num_keys];
        for(int i = 0; i < num_keys; i++) {
            keys[i] = NULL;    
        }

        max_keys = num_keys;
    } catch(const exception& e) {
        delete[] iv;
        delete[] session_key;
        delete[] keys;
        cerr << e.what() << endl;
    }          
}

Crypto::~Crypto() {
    delete[] iv;
    delete[] session_key;
    delete[] keys;
}

void Crypto::insertKey(unsigned char *key, unsigned int pos) {
    if(pos > max_keys)
        throw runtime_error("Position exceeds keys array.");
    
    try {
        keys[pos] = new unsigned char[DIGEST_LEN];
        for(int i = 0; i < DIGEST_LEN; i++) {
            keys[pos][i] = key[i];
        }
    } catch(const exception& e) {
        delete[] keys[pos];
        throw;
    }
}

void Crypto::setSessionKey(unsigned int key) {
    if(!keys[key])
        throw runtime_error("Key not exists.");

    for(int i = 0; i < DIGEST_LEN; i++) {
        session_key[i] = keys[key][i];
    }
}

void Crypto::generateNonce(unsigned char* nonce) {
    if(RAND_poll() != 1)
        throw runtime_error("An error occurred in RAND_poll."); 
    if(RAND_bytes(nonce, NONCE_SIZE) != 1)
        throw runtime_error("An error occurred in RAND_bytes.");
}

void Crypto::generateIV() {
    if(RAND_poll() != 1)
        throw runtime_error("An error occurred in RAND_poll."); 
    if(RAND_bytes(iv, IV_SIZE) != 1)
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
    if(fclose(file)!=0)
        throw runtime_error("An error occurred while closing the file.");
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
    if(fclose(file)!=0)
        throw runtime_error("An error occurred while closing the file.");
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
    if(fclose(file)!=0)
        throw runtime_error("An error occurred while closing the file.");
}

int Crypto::publicKeyEncryption(unsigned char *msg, unsigned int msg_len, unsigned char *buff, EVP_PKEY *pubkey){
    unsigned char *ciphertext = NULL;
    unsigned char *encrypted_key = NULL;
    unsigned char *iv = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int encrypted_key_len;
    int outlen;
    int cipherlen;
    int start = 0;
    try{
        encrypted_key = new unsigned char[EVP_PKEY_size(pubkey)];
        ciphertext = new unsigned char[msg_len + 16];
        ctx = EVP_CIPHER_CTX_new();
        if(ctx == NULL){
            throw runtime_error("An error occurred creating the context during the public key encryption");
        }
        iv = new unsigned char[EVP_CIPHER_iv_length(CIPHER)];
        if(EVP_SealInit(ctx, CIPHER, &encrypted_key, &encrypted_key_len, iv, &pubkey, 1)==0){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("An error occurred initializing the envelope.");
        }
        if(EVP_SealUpdate(ctx, ciphertext, &outlen, (unsigned char *)msg, msg_len)==0){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("An error occurred updating the envelope.");
        }
        cipherlen = outlen; 
        if(EVP_SealFinal(ctx, ciphertext+cipherlen, &outlen)==0){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("An error occurred finishing the envelop.");
        }
        cipherlen+=outlen;
        memcpy(buff, iv, EVP_CIPHER_iv_length(CIPHER));
        start+=EVP_CIPHER_iv_length(CIPHER);
        memcpy(buff+start,encrypted_key,encrypted_key_len);
        start+=encrypted_key_len;
        memcpy(buff+start, ciphertext, cipherlen);
        start+=cipherlen;
        EVP_CIPHER_CTX_free(ctx);
    }catch (const exception &e) {
        delete[] encrypted_key;
        delete[] ciphertext;
        delete[] iv;
        throw;
    }
    delete[] encrypted_key;
    delete[] ciphertext;
    delete[] iv;
    return start;
}

int Crypto::publicKeyDecryption(unsigned char *msg, unsigned int msg_len, unsigned char *buff, EVP_PKEY *prvkey){
    unsigned char *plaintext = NULL;
    unsigned char *encrypted_key = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *iv = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int start = 0;
    int outlen, plainlen;
    try{
        plaintext = new unsigned char[msg_len];
        iv = new unsigned char[EVP_CIPHER_iv_length(CIPHER)];
        encrypted_key = new unsigned char[EVP_PKEY_size(prvkey)];
        ciphertext = new unsigned char[msg_len-EVP_CIPHER_iv_length(CIPHER)-EVP_PKEY_size(prvkey)];
        memcpy(iv,msg,EVP_CIPHER_iv_length(CIPHER));
        start+=EVP_CIPHER_iv_length(CIPHER);
        memcpy(encrypted_key,msg+start,EVP_PKEY_size(prvkey));
        start+=EVP_PKEY_size(prvkey);
        memcpy(ciphertext, msg+start,msg_len-start);
        ctx = EVP_CIPHER_CTX_new();
        if(ctx == NULL){
            throw runtime_error("An error occurred initializing the context");
        }
        if(EVP_OpenInit(ctx, CIPHER, encrypted_key, EVP_PKEY_size(prvkey), iv, prvkey)==0){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("An error occurred initializing the envelope.");
        }
        if(EVP_OpenUpdate(ctx,plaintext, &outlen, ciphertext, msg_len-start)==0){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("An error occurred updating the envelope.");
        }
        plainlen = outlen;
        if(EVP_OpenFinal(ctx,plaintext+plainlen,&outlen)==0){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("An error occurred finishing the envelope.");
        }
        plainlen+=outlen;
        memcpy(buff,plaintext,plainlen);
        EVP_CIPHER_CTX_free(ctx);
    }catch (const exception &e) {
        delete[] plaintext;
        delete[] iv;
        delete[] encrypted_key;
        delete[] ciphertext;
        throw;
    }
    delete[] plaintext;
    delete[] iv;
    delete[] encrypted_key;
    delete[] ciphertext;
    return plainlen;
}

void Crypto::getPublicKeyFromCertificate(X509 *cert, EVP_PKEY *&pubkey){
    pubkey = X509_get_pubkey(cert);
}

int Crypto::encryptMessage(unsigned char *msg, int msg_len, unsigned char *buffer) {
    unsigned char *ciphertext = NULL;
    unsigned char *tag = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned int start = 0;
    int len = 0;
    int ciphr_len = 0;

    try {
        generateIV();
        ciphertext = new unsigned char[msg_len + TAG_SIZE];
        tag = new unsigned char[TAG_SIZE];

        ctx = ctx = EVP_CIPHER_CTX_new();
        if(!ctx)
            throw runtime_error("An error occurred while creating the context.");   

        // QUESTION: Bisogna fare la free in questi casi di errore?
        if(EVP_EncryptInit(ctx, AUTH_ENCR, session_key, iv) != 1)
            throw runtime_error("An error occurred while initializing the context.");
            
        //AAD: header in the clear that contains the IV
        if(EVP_EncryptUpdate(ctx, NULL, &len, iv, IV_SIZE) != 1)
            throw runtime_error("An error occurred in adding AAD header.");
            
        if(EVP_EncryptUpdate(ctx, ciphertext, &len, msg, msg_len) != 1)
            throw runtime_error("An error occurred while encrypting the message.");
        ciphr_len = len;

        if(EVP_EncryptFinal(ctx, ciphertext + len, &len) != 1)
            throw runtime_error("An error occurred while finalizing the ciphertext.");
        ciphr_len += len;

        //Get the tag
        if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag) != 1)
            throw runtime_error("An error occurred while getting the tag.");
        
        memcpy(buffer+start, iv, IV_SIZE);
        start += IV_SIZE;
        memcpy(buffer+start, ciphertext, ciphr_len);
        start += ciphr_len;
        memcpy(buffer+start, tag, TAG_SIZE);
        start += TAG_SIZE;
    } catch(const exception& e) {
        delete[] ciphertext;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    
    delete[] ciphertext;
    delete[] tag;
    EVP_CIPHER_CTX_free(ctx);
    return start;
}

int Crypto::decryptMessage(unsigned char *msg, int msg_len, unsigned char *buffer) {
    unsigned char *recv_iv;
    unsigned char *recv_tag;
    unsigned char *ciphr_msg;
    EVP_CIPHER_CTX *ctx;
    unsigned int ciphr_len = 0;
    int ret = 0;
    int len = 0;
    int pl_len = 0;

    try
    {
        recv_iv = new unsigned char[IV_SIZE];
        memcpy(recv_iv, msg, IV_SIZE);
        recv_tag = new unsigned char[TAG_SIZE];
        memcpy(recv_tag,msg+msg_len-TAG_SIZE, TAG_SIZE);
        ciphr_len = msg_len - IV_SIZE - TAG_SIZE;
        ciphr_msg = new unsigned char[ciphr_len];
        memcpy(ciphr_msg, msg+IV_SIZE, ciphr_len);

        ctx = EVP_CIPHER_CTX_new();
        if(!ctx)
            throw runtime_error("An error occurred while creating the context.");

        if(!EVP_DecryptInit(ctx, AUTH_ENCR, session_key, recv_iv))
            throw runtime_error("An error occurred while initializing the context.");
        
        if(!EVP_DecryptUpdate(ctx, NULL, &len, recv_iv, IV_SIZE))
            throw runtime_error("An error occurred while getting AAD header.");
            
        if(!EVP_DecryptUpdate(ctx, buffer, &len, ciphr_msg, ciphr_len))
            throw runtime_error("An error occurred while decrypting the message");
        pl_len = len;
        
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, recv_tag))
            throw runtime_error("An error occurred while setting the expected tag.");
        
        ret = EVP_DecryptFinal(ctx, buffer + len, &len);
    } catch(const exception& e) {
        delete[] recv_iv;
        delete[] recv_tag;
        delete[] ciphr_msg;
        //QUESTION: che differenza c'è tra free e cleanup?
        //EVP_CIPHER_CTX_cleanup(ctx);
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }

    delete[] recv_iv;
    delete[] recv_tag;
    delete[] ciphr_msg;
    EVP_CIPHER_CTX_free(ctx);
    
    if(ret > 0)
        pl_len += len; 
    else
        pl_len = -1;

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
    if(fclose(file)!=0)
        throw runtime_error("An error occurred while closing the file.");
}

int Crypto::serializeCertificate(X509* cert, unsigned char* cert_buf){
    int cert_size = i2d_X509(cert,&cert_buf);
    if(cert_size<0)
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
    if(!file) { 
        throw runtime_error("An error occurred opening crl.pem.");
    }
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
    if(store == NULL)
        throw runtime_error("An error occured during the allocation of the store");
    if(X509_STORE_add_cert(store, ca_cert)<1){
        X509_STORE_free(store);
        throw runtime_error("An error occurred adding the certification to the store");
    }
    if(X509_STORE_add_crl(store, crl)<1){
        X509_STORE_free(store);
        throw runtime_error("An error occurred adding the crl to the store");
    }
    if(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK)<1){
        X509_STORE_free(store);
        throw runtime_error("An error occurred adding the flags to the store");
    }
    if(X509_STORE_CTX_init(ctx, store, cert_to_verify, NULL)==0){
        X509_STORE_free(store);
        throw runtime_error("An error occurred during the initialization of the context");
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

int Crypto::serializePublicKey(EVP_PKEY *prv_key, unsigned char *pubkey_buf){
    BIO *mbio;
    unsigned char *buffer;
    long pubkey_size; 

    mbio = BIO_new(BIO_s_mem());

    if(!mbio)
        throw runtime_error("An error occurred during the creation of the bio.");

    if(PEM_write_bio_PUBKEY(mbio,prv_key) != 1){
        BIO_free(mbio);
        throw runtime_error("An error occurred during the writing of the public key into the bio.");
    }

    pubkey_size = BIO_get_mem_data(mbio, &buffer);
    memcpy(pubkey_buf, buffer, pubkey_size);

    if(pubkey_size < 0){
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

    if(EVP_DigestInit(ctx, HASH) < 1){
        EVP_MD_CTX_free(ctx);
        throw runtime_error("An error occurred during the initialization of the digest.");
    }

    if(EVP_DigestUpdate(ctx, msg, msg_size) < 1){
        EVP_MD_CTX_free(ctx);
        throw runtime_error("An error occurred during the creation of the digest.");
    } 

    if(EVP_DigestFinal(ctx, digest, &len) < 1){
        EVP_MD_CTX_free(ctx);
        throw runtime_error("An error occurred during the conclusion of the digest.");
    }

    EVP_MD_CTX_free(ctx);
}

void Crypto::buildParameters(EVP_PKEY *&dh_params) {
    DH *temp;
    dh_params = EVP_PKEY_new();

    if(!dh_params) {
        throw runtime_error("An error occurred during the allocation of parameters.");
    }

    temp = DH_get_2048_224();

    if(EVP_PKEY_set1_DH(dh_params,temp) == 0){
        DH_free(temp);
        //malloc: *** error for object 0x102bc0260: pointer being freed was not allocated
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
    
    if(EVP_PKEY_keygen_init(ctx) < 1) {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("An error occurred during the intialization of the context");
    }

    if(EVP_PKEY_keygen(ctx, &my_prvkey) < 1) {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("An error occurred during the intialization of the context");
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

    if(EVP_PKEY_derive_init(ctx_drv) < 1) {
        EVP_PKEY_CTX_free(ctx_drv);
        throw runtime_error("An error occurred during the intialization of the context.");
    }

    if(EVP_PKEY_derive_set_peer(ctx_drv, peer_pubkey) < 1) {
        EVP_PKEY_CTX_free(ctx_drv);
        throw runtime_error("An error occurred setting the peer's public key.");
    }

    if(EVP_PKEY_derive(ctx_drv, NULL, &secretlen) < 1) {
        EVP_PKEY_CTX_free(ctx_drv);
        throw runtime_error("An error occurred retrieving the secret length.");
    }

    secret = (unsigned char*)OPENSSL_malloc(secretlen);

    if(!secret) {
        EVP_PKEY_CTX_free(ctx_drv);
        throw runtime_error("An error occurred allocating the unsigned char array.");
    }

    if(EVP_PKEY_derive(ctx_drv, secret, &secretlen) < 1) {
        EVP_PKEY_CTX_free(ctx_drv);
        OPENSSL_free(secret);
        throw runtime_error("An error occurred during the derivation of the secret.");
    }

    EVP_PKEY_CTX_free(ctx_drv);
    computeHash(secret, secretlen, buffer);
    OPENSSL_free(secret);
}