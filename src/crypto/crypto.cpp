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
    unsigned char* ret_iv = new unsigned char[IV_SIZE];

    for(int i = 0; i < IV_SIZE; i++) {
        ret_iv[i] = iv[i];
    }

    return ret_iv;
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

