#include "include/crypto.h"

Crypto::Crypto(unsigned char *sk) {
    try {
            iv = new unsigned char[IV_SIZE];
            for(int i = 0; i < IV_SIZE; i++) {
                iv[i] = 0;
            }

            session_key = new unsigned char[DIGEST_LEN];
            for(int i = 0; i < DIGEST_LEN; i++) {
                    session_key[i] = sk[i];
            }
    } catch(const exception& e) {
            delete[] iv;
            delete[] session_key;
            cerr << e.what() << endl;
    }          
}

Crypto::~Crypto() {
            delete[] iv;
            delete[] session_key;
}

void Crypto::setSessionKey(unsigned char *secret) {
    for(int i = 0; i < DIGEST_LEN; i++) {
        session_key[i] = secret[i];
    }
}

string Crypto::generateNonce() { 
    unsigned char nonce_buf[16];
    string nonce;

    if(RAND_poll() != 1)
        throw runtime_error("An error occurred in RAND_poll."); 
    if(RAND_bytes(nonce_buf, 16) != 1)
        throw runtime_error("An error occurred in RAND_bytes.");
    
    for (size_t i = 0; i < 16; i++) {
        nonce.append(1, static_cast<char>(nonce_buf[i]));
    }
    return nonce;
}

void Crypto::generateIV() {
    if(RAND_poll() != 1)
        throw runtime_error("An error occurred in RAND_poll."); 
    if(RAND_bytes(iv, IV_SIZE) != 1)
        throw runtime_error("An error occurred in RAND_bytes.");
}

unsigned char* Crypto::getIV() {
    return iv;
}

EVP_PKEY* Crypto::readPrivateKey(string pwd) {
    //QUESTION: necessario controllo su pwd tramite white/black list??
    EVP_PKEY* prvKey;
    FILE* file;
    file = fopen("prvkey.pem", "r");
    if(!file)
        throw runtime_error("An error occurred, the file doesn't exist.");
    prvKey = PEM_read_PrivateKey(file, NULL, NULL, (char*)pwd.c_str());
    if(!prvKey){
        fclose(file);
        throw runtime_error("An error occurred while reading the private key.");
    }
    if(fclose(file)!=0)
        throw runtime_error("An error occurred while closing the file.");
    return prvKey;
}

EVP_PKEY* Crypto::readPublicKey(string user) {
    //QUESTION: necessario controllo su user tramite white/black list??
    EVP_PKEY* pubKey;
    FILE* file;
    string path = user + "_pubkey.pem";
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
    return pubKey;
}

int Crypto::encryptMessage(unsigned char *msg, int msg_len,
                        unsigned char *ciphr_msg,
                        unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ciphr_len = 0;
    generateIV();

    if(!(ctx = EVP_CIPHER_CTX_new()))
        throw runtime_error("An error occurred while creating the context.");   

    if(EVP_EncryptInit(ctx, AUTH_ENCR, session_key, iv) != 1) {
        // QUESTION: Bisogna fare la free in questi casi di errore?
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("An error occurred while initializing the context.");
    }
         
    //AAD: header in the clear that contains the IV
    if(EVP_EncryptUpdate(ctx, NULL, &len, iv, IV_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("An error occurred in adding AAD header.");
    }
        
    // TODO: Controllare se server un for
    if(EVP_EncryptUpdate(ctx, ciphr_msg, &len, msg, msg_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("An error occurred while encrypting the message.");
    }
    ciphr_len = len;

    if(EVP_EncryptFinal(ctx, ciphr_msg + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("An error occurred while finalizing the ciphertext.");
    }
    ciphr_len += len;

    //Get the tag
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("An error occurred while getting the tag.");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return ciphr_len;
}

int Crypto::decryptMessage(unsigned char *ciphr_msg, int ciphr_len,
                        unsigned char* iv_src,
                        unsigned char* tag, 
                        unsigned char *msg) {
    EVP_CIPHER_CTX *ctx;
    int ret;
    int len;
    int pl_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        throw runtime_error("An error occurred while creating the context.");

    if(!EVP_DecryptInit(ctx, AUTH_ENCR, session_key, iv_src)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("An error occurred while initializing the context.");
    }
    
    if(!EVP_DecryptUpdate(ctx, NULL, &len, iv_src, IV_SIZE)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("An error occurred while getting AAD header.");
    }
        
    if(!EVP_DecryptUpdate(ctx, msg, &len, ciphr_msg, ciphr_len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("An error occurred while decrypting the message");
    }
    pl_len = len;
    
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("An error occurred while setting the expected tag.");
    }
    
    ret = EVP_DecryptFinal(ctx, msg + len, &len);

    //QUESTION: che differenza c'è tra free e cleanup?
    //EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        pl_len += len;
        return pl_len;
    } else {
        return -1;
    }
}

X509* Crypto::loadCertificate(){
    X509 *cert = NULL;
    FILE *file = fopen(CA_CERT_PATH,"r");
    if(!file)
        throw runtime_error("An error occurred while opening the file.");
    cert = PEM_read_X509(file,NULL,NULL,NULL);
    if(!cert){
        fclose(file);
        throw runtime_error("An error occurred while reading the pem certificate.");
    }
    if(fclose(file)!=0)
        throw runtime_error("An error occurred while closing the file.");
    return cert;
}

int Crypto::sendCertificate(X509* cert, unsigned char* cert_buf){
    int cert_size = i2d_X509(cert,&cert_buf);
    if(cert_size<0)
        throw runtime_error("An error occurred during the writing of the certificate.");
    return cert_size;
}

X509* Crypto::receiveCertificate(int cert_len,unsigned char* cert_buff){
    X509 *buff = d2i_X509(NULL,(const unsigned char**)&cert_buff,cert_len);
    if(!buff)
        throw runtime_error("An error occurred during the reading of the certificate.");
    return buff;
}

X509_CRL* Crypto::loadCRL() {
    X509_CRL* crl;
    FILE* file = fopen("crl.pem", "r");
    if(!file) { 
        throw runtime_error("An error occurred opening crl.pem.");
    }
    crl = PEM_read_X509_CRL(file, NULL, NULL, NULL); 
    if(!crl) { 
        fclose(file);
        throw runtime_error("An error occurred reading the crl from file");
    }
    fclose(file);
    return crl;
}

bool Crypto::verifyCertificate(unsigned char* cert_buff, int cert_len) {
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509* ca_cert;
    X509_STORE* store;
    X509_CRL* crl;

    ca_cert = loadCertificate();
    crl = loadCRL();

    store = X509_STORE_new();
    X509_STORE_add_cert(store, ca_cert);
    X509_STORE_add_crl(store, crl);
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);

    X509_STORE_CTX_init(ctx, store, ca_cert, NULL);
    int ret = X509_verify_cert(ctx);
    if(ret != 1) { 
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