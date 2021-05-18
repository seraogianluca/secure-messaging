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

unsigned char* Crypto::generateNonce(){ 
    unsigned char nonce[16];
    if(RAND_poll() != 1)
        throw "An error occurred in RAND_poll."; 
    if(RAND_bytes(nonce, 16) != 1)
        throw "An error occurred in RAND_bytes.";
    return nonce;
}

int Crypto::encryptMessage(unsigned char *msg, unsigned char *ciphr_msg, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[IV_SIZE];
    int len = 0;
    int ciphr_len = 0;

    // Generate a random IV
    // TODO: controllare se va bene generarlo per ogni messaggio
    if(RAND_poll() != 1)
        throw "An error occurred in RAND_poll.";
    if(RAND_bytes(iv, IV_SIZE) != 1)
        throw "An error occurred in RAND_bytes.";
    
    if(!(ctx = EVP_CIPHER_CTX_new()))
        throw "An error occurred while creating the context.";   

    if(EVP_EncryptInit(ctx, AUTH_ENCR, session_key, iv) != 1)
        throw "An error occurred while initializing the context.";
    
    //AAD: header in the clear that contains the IV
    if(EVP_EncryptUpdate(ctx, NULL, &len, iv, IV_SIZE) != 1)
        throw "An error occurred in adding AAD header.";
    
    // TODO: Controllare se server un for
    if(EVP_EncryptUpdate(ctx, ciphr_msg, &len, msg, sizeof msg) != 1)
        throw "An error occurred while encrypting the message.";
    ciphr_len = len;

    if(EVP_EncryptFinal(ctx, ciphr_msg + len, &len) != 1)
        throw "An error occurred while finalizing the ciphertext.";
    ciphr_len += len;

    //Get the tag
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag) != 1)
        throw "An error occurred while getting the tag.";
    
    EVP_CIPHER_CTX_free(ctx);
    return ciphr_len;
}

int Crypto::decryptMessage(unsigned char *ciphr_msg, unsigned char *msg) {
    EVP_CIPHER_CTX *ctx;
    int ret;
    int len;
    int pl_len;
    unsigned char *header;

    unsigned char *iv;
    iv = (unsigned char*)malloc(IV_SIZE);
    if(!iv) {
        free(iv);
        throw "An error occurred while allocating the iv."; 
    }
        
    if(memccpy(iv, ciphr_msg, 0, IV_SIZE) == NULL) {
        free(iv);
        throw "An error occurred while copying the iv.";
    }

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        free(iv);
        throw "An error occurred while creating the context.";
    }

    if(!EVP_DecryptInit(ctx, AUTH_ENCR, session_key, iv)) {
        free(iv);
        throw "An error occurred while initializing the context.";
    }
    
    if(!EVP_DecryptUpdate(ctx, NULL, &len, header, IV_SIZE)) {
        free(iv);
        throw "An error occurred while getting AAD header.";
    }
        
    int ciphr_len =  sizeof ciphr_msg - IV_SIZE;   
    if(!EVP_DecryptUpdate(ctx, msg, &len, ciphr_msg, ciphr_len)) {
        free(iv);
        throw "An error occurred while decrypting the message";
    }
    pl_len = len;
    
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, tag)) {
        free(iv);
        throw "An error occurred while setting the expected tag.";
    }
    
    ret = EVP_DecryptFinal(ctx, msg + len, &len);

    EVP_CIPHER_CTX_cleanup(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}

