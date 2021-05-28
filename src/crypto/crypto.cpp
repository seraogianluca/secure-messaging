#include "include/crypto.h"

unsigned char* Crypto::stringToChar(string str) {
    size_t buf_size = str.length();
    unsigned char ret[buf_size+1];
    strncpy((char*)ret,str.c_str(),buf_size+1);
    return ret;
}

string Crypto::charToString(unsigned char* str) {
    return string((char*)str);
}

EVP_PKEY* Crypto::readPrivateKey(string pwd) {
    //QUESTION: necessario controllo su pwd tramite white/black list??
    EVP_PKEY* prvKey;
    FILE* file;
    file = fopen("prvkey.pem", "r");
    if(!file)
        throw "An error occurred, the file doesn't exist.";
    prvKey = PEM_read_PrivateKey(file, NULL, NULL, (char*)pwd.c_str());
    if(!prvKey){
        fclose(file);
        throw "An error occurred while reading the private key.";
    }
    if(fclose(file)!=0)
        throw "An error occurred while closing the file.";
    return prvKey;
}

EVP_PKEY* Crypto::readPublicKey(string user) {
    //QUESTION: necessario controllo su user tramite white/black list??
    EVP_PKEY* pubKey;
    FILE* file;
    string path = user + "_pubkey.pem";
    file = fopen(path.c_str(), "r");
    if(!file)
        throw "An error occurred, the file doesn't exist.";
    pubKey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if(!pubKey){
        fclose(file);
        throw "An error occurred while reading the private key.";
    }
    if(fclose(file)!=0)
        throw "An error occurred while closing the file.";
    return pubKey;
}

string Crypto::generateNonce() { 
    unsigned char nonce_buf[16];
    string nonce;

    if(RAND_poll() != 1)
        throw "An error occurred in RAND_poll."; 
    if(RAND_bytes(nonce_buf, 16) != 1)
        throw "An error occurred in RAND_bytes.";
    
    for (size_t i = 0; i < 16; i++) {
        nonce.append(1, static_cast<char>(nonce_buf[i]));
    }
    return nonce;
}

int Crypto::generateIV() {
    iv = new unsigned char[IV_SIZE];

    if(RAND_poll() != 1)
        throw "An error occurred in RAND_poll."; 
    if(RAND_bytes(iv, IV_SIZE) != 1)
        throw "An error occurred in RAND_bytes.";

    return 0;
}

unsigned char* Crypto::getIV() {
    return iv;
}

int Crypto::encryptMessage(unsigned char *msg, int msg_len,
                        unsigned char *ciphr_msg,
                        unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ciphr_len = 0;
    generateIV();

    if(!(ctx = EVP_CIPHER_CTX_new()))
        throw "An error occurred while creating the context.";   

    if(EVP_EncryptInit(ctx, AUTH_ENCR, session_key, iv) != 1) {
        // QUESTION: Bisogna fare la free in questi casi di errore?
        EVP_CIPHER_CTX_free(ctx);
        throw "An error occurred while initializing the context.";
    }
         
    //AAD: header in the clear that contains the IV
    if(EVP_EncryptUpdate(ctx, NULL, &len, iv, IV_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw "An error occurred in adding AAD header.";
    }
        
    // TODO: Controllare se server un for
    if(EVP_EncryptUpdate(ctx, ciphr_msg, &len, msg, msg_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw "An error occurred while encrypting the message.";
    }
    ciphr_len = len;

    if(EVP_EncryptFinal(ctx, ciphr_msg + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw "An error occurred while finalizing the ciphertext.";
    }
    ciphr_len += len;

    //Get the tag
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw "An error occurred while getting the tag.";
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
        throw "An error occurred while creating the context.";

    if(!EVP_DecryptInit(ctx, AUTH_ENCR, session_key, iv_src)) {
        EVP_CIPHER_CTX_free(ctx);
        throw "An error occurred while initializing the context.";
    }
    
    if(!EVP_DecryptUpdate(ctx, NULL, &len, iv_src, IV_SIZE)) {
        EVP_CIPHER_CTX_free(ctx);
        throw "An error occurred while getting AAD header.";
    }
        
    if(!EVP_DecryptUpdate(ctx, msg, &len, ciphr_msg, ciphr_len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw "An error occurred while decrypting the message";
    }
    pl_len = len;
    
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        throw "An error occurred while setting the expected tag.";
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
        throw "An error occurred while opening the file.";
    cert = PEM_read_X509(file,NULL,NULL,NULL);
    if(!cert){
        fclose(file);
        throw "An error occurred while reading the pem certificate.";
    }
    if(fclose(file)!=0)
        throw "An error occurred while closing the file.";
    return cert;
}

int Crypto::sendCertificate(int sock, X509* cert, unsigned char* cert_buf){
    int cert_size = i2d_X509(cert,&cert_buf);
    if(cert_size<0)
        throw "An error occurred during the writing of the certificate.";
    return cert_size;
}

X509* Crypto::receiveCertificate(int sock,int cert_len,unsigned char* cert_buff){
    X509 *buff = d2i_X509(NULL,(const unsigned char**)&cert_buff,cert_len);
    if(!buff)
        throw "An error occurred during the reading of the certificate.";
    return buff;
}

int Crypto::sendPublicKey(EVP_PKEY* pubkey, unsigned char* pubkey_buf){
    BIO *mbio = BIO_new(BIO_s_mem());
    if(mbio==NULL)
        throw "An error occurred during the creation of the bio.";
    if(PEM_write_bio_PUBKEY(mbio,pubkey)!=1){
        BIO_free(mbio);
        throw "An error occurred during the writing of the public key into the bio.";
    }
    long pubkey_size = BIO_get_mem_data(mbio,&pubkey_buf);
    if(pubkey_size<0){
        BIO_free(mbio);
        throw "An error occurred during the reading of the public key.";
    }
    BIO_free(mbio);
    return pubkey_size;
}

EVP_PKEY* Crypto::receivePublicKey(unsigned char* pubkey_buf, int pubkey_size){
    BIO *mbio = BIO_new(BIO_s_mem());
    if(mbio==NULL)
        throw "An error occurred during the creation of the bio.";
    if(BIO_write(mbio,pubkey_buf,pubkey_size)<=0)
        throw "An error occurred during the writing of the bio.";
    EVP_PKEY *pubkey = PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
    if(pubkey == NULL){
        BIO_free(mbio);
        throw "An error occurred during the reading of the public key from the bio.";
    }
    BIO_free(mbio);
    return pubkey;
}

unsigned char* Crypto::computeHash(unsigned char* msg, unsigned int msg_size) {
    unsigned char digest[DIGEST_LEN];
    unsigned int digestlen;
    EVP_MD_CTX* ctx;

    ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, HASH);
    EVP_DigestUpdate(ctx, msg, msg_size); 
    EVP_DigestFinal(ctx, digest, &digestlen);
    EVP_MD_CTX_free(ctx);
    
    return digest;
}