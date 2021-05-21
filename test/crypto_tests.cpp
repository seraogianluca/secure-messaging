#include "include/crypto.h"
#include <sstream>

string str_to_hex(string str) {
    stringstream ss; 
    for (int i = 0; i < str.length(); i++)
        ss << hex << (int)str[i] << " ";
    return ss.str();
}

void nonce_test() {
    Crypto c((unsigned char*)"1234567890123456");

    // Nonce test
    string nonce;

    cout << "NONCE TEST:" << endl;

    try {    
        nonce = c.generateNonce();
        cout << "Length: " << nonce.length() << endl;
        cout << "Nonce: ";
        cout << str_to_hex(nonce) << endl;
    } catch(const char *msg) {
        cerr << msg << endl;
    }
}

void auth_encrypt_test() {
    Crypto c((unsigned char*)"1234567890123456");
    unsigned char msg[] = "Test message";
    unsigned char *ciphertext;
    unsigned char *tag;
    unsigned char *iv;
    unsigned char *dec_msg; 
    int ciphertext_len;
    int plaintext_len = sizeof(msg);

    cout << "ENCRYPTION TEST:" << endl;

    try {
        ciphertext = (unsigned char*)malloc(plaintext_len+TAG_SIZE);
        tag = (unsigned char*)malloc(TAG_SIZE);
        ciphertext_len = c.encryptMessage(msg, 
                                        plaintext_len, 
                                        ciphertext, 
                                        tag);
        cout << "Ciphertext:" << endl;
        BIO_dump_fp(stdout, (const char*)ciphertext, ciphertext_len);
        cout << "Tag:" << endl;
        BIO_dump_fp(stdout, (const char*)tag, TAG_SIZE);

    } catch(const char *msg) {
        cerr << msg << endl;
    }
    iv = c.getIV();
    try {

        dec_msg = (unsigned char*)malloc(ciphertext_len);
        plaintext_len = c.decryptMessage(ciphertext,
                                        ciphertext_len,
                                        iv,
                                        tag,
                                        dec_msg);
        if(plaintext_len == -1)
            cout << "Not corresponding tag." << endl;
        else {
            cout<<"Plaintext:"<<endl;
	        BIO_dump_fp (stdout, (const char *)dec_msg, plaintext_len);
        }
    } catch(const char* msg) {
        cerr << msg << endl;
    }

    free(ciphertext);
    free(tag);
    free(dec_msg);
}

int main() {

    // Encryption test
    

    
}