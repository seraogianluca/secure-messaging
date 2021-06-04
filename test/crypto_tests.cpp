#include "include/crypto.h"

void auth_encrypt_test() {
    Crypto *crypto = NULL;
    unsigned char msg[] = "Test message";
    unsigned char *ciphertext;
    unsigned char *dec_msg; 
    int ciphertext_len;
    int plaintext_len;

    crypto = new Crypto(1);
    crypto->insertKey((unsigned char*)"1234567890123456", 0);
    crypto->setSessionKey(0);

    cout << "ENCRYPTION TEST:" << endl;
    plaintext_len = sizeof(msg);
    ciphertext = new (nothrow) unsigned char[plaintext_len+TAG_SIZE];
    if(!ciphertext){
        delete crypto;
        cerr << "Array not initialized";
        return;
    }

    try {
        ciphertext_len = crypto->encryptMessage(msg, plaintext_len, ciphertext);
        cout << "Ciphertext:" << endl;
        BIO_dump_fp(stdout, (const char*)ciphertext, ciphertext_len);

    } catch(const exception& e) {
        delete crypto;
        delete[] ciphertext;
        cerr << e.what() << endl;
        return;
    }

    cout << "DECRYPTION TEST:" << endl;
    dec_msg = new (nothrow) unsigned char[ciphertext_len];
    if(!dec_msg){
        delete crypto;
        delete[] ciphertext;
        cerr << "Array not initialized";
        return;
    }

    try {
        plaintext_len = crypto->decryptMessage(ciphertext, ciphertext_len, dec_msg);
        if(plaintext_len == -1)
            cout << "Not corresponding tag." << endl;
        else {
            cout<<"Plaintext:"<<endl;
	        BIO_dump_fp (stdout, (const char *)dec_msg, plaintext_len);
        }
    } catch(const exception& e) {
        delete crypto;
        delete[] ciphertext;
        delete[] dec_msg;
        cerr << e.what() << endl;
        return;
    }

    delete crypto;
    delete[] ciphertext;
    delete[] dec_msg;
}

int main() {
    cout << "<-- TEST UNIT --->" << endl;
    auth_encrypt_test();

    return 0;
}