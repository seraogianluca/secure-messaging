#include "include/crypto.h"

int main() {
    Crypto c((unsigned char*)"1234567890123456");
    
    // Nonce test
    unsigned char *nonce;
    nonce = c.generateNonce();
    cout << nonce << endl;

    // Encryption test
    unsigned char msg[] = "Test message";
    unsigned char *ciphertext;
    unsigned char *tag;
    
    int ciphertext_len;
    int tag_len = TAG_SIZE;
    int plaintext_len = sizeof(msg);

    ciphertext = (unsigned char*)malloc(plaintext_len+TAG_SIZE);
    tag = (unsigned char*)malloc(TAG_SIZE);

    ciphertext_len = c.encryptMessage(msg, ciphertext, tag);
    cout << "CT:" << endl;
    BIO_dump_fp(stdout, (const char*)ciphertext, ciphertext_len);
    cout << "Tag:" << endl;
    BIO_dump_fp(stdout, (const char*)tag, TAG_SIZE);

    // AAD (12) | MSG (ANY*) | TAG (16)
    unsigned char *msg2 = (unsigned char*)malloc(ciphertext_len+TAG_SIZE);
    memcpy(msg2, ciphertext, ciphertext_len);
    memcpy(msg2+ciphertext_len, tag, TAG_SIZE);

    unsigned char *dec_msg;
    dec_msg = (unsigned char*)malloc(ciphertext_len);
    plaintext_len = c.decryptMessage(msg2, dec_msg);
    if(plaintext_len == -1)
        cout << "Not corresponding tag." << endl;
    else {
        cout<<"PT:"<<endl;
	    BIO_dump_fp (stdout, (const char *)dec_msg, plaintext_len);
    }
}