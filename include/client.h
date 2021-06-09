#include "socket.h"
#include "crypto.h"
#include <iterator>
#include <array>
#include <cstring>
#include <algorithm>
#include <termios.h>

//TODO: serve costruttore con parametri di default per fare solo dichiarazione
Crypto crypto(2);
SocketClient socketClient(SOCK_STREAM);

void setStdinEcho(bool enable = true) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if(!enable)
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

string readPassword() {
    string password;
    cout << "Insert password: ";
    setStdinEcho(false);
    cin >> password;
    cin.ignore();
    setStdinEcho(true);
    cout << endl;
    return password;
}

string readFromStdout(string message) {
    string value;
    cout << message;
    
    do {
        getline(cin, value);
        if(value.length() == 0) {
            cout << "Insert at least a character." << endl;
            cout << message;
        }
    } while (value.length() == 0);
    
    return value;
}

// ---------- AUTHENTICATION ---------- //

void sendPassword(unsigned char *nonce, string password, string username, X509 *cert) {
    EVP_PKEY *server_pubkey = NULL;
    vector<unsigned char> message;
    array<unsigned char, MAX_MESSAGE_SIZE> buffer;
    unsigned char *pwdDigest = NULL;
    unsigned int ciphertextLen = 0;
    try {
        pwdDigest = new (nothrow) unsigned char[DIGEST_LEN];

        if(!pwdDigest)
            throw runtime_error("An error occurred while allocating the buffer.");

        crypto.computeHash((unsigned char *) password.c_str(), password.length(), pwdDigest);
        message.insert(message.end(), pwdDigest, pwdDigest + DIGEST_LEN);
        message.insert(message.end(), nonce, nonce + NONCE_SIZE);
        crypto.computeHash(message.data(), DIGEST_LEN + NONCE_SIZE, pwdDigest);
        crypto.getPublicKeyFromCertificate(cert,server_pubkey);
        ciphertextLen = crypto.publicKeyEncryption(pwdDigest, DIGEST_LEN, buffer.data(), server_pubkey);
        socketClient.sendMessage(socketClient.getMasterFD(), buffer.data(), ciphertextLen);

        delete[] pwdDigest;
    } catch(const exception& e) {
        if(pwdDigest != nullptr) delete[] pwdDigest;
        throw;
    }
}

void authentication(string username, string password) {
    X509 *cert;
    EVP_PKEY *prvkey = NULL;
    array<unsigned char,MAX_MESSAGE_SIZE> buffer;
    array<unsigned char,NONCE_SIZE> nonceClient;
    array<unsigned char,NONCE_SIZE> nonceServer;
    unsigned char *plaintext = NULL;
    unsigned int messageReceivedLen;
    unsigned int plainlen;
    try {
        crypto.readPrivateKey(username,password,prvkey);

        // Generate nonce
        crypto.generateNonce(nonceClient.data());

        // Build hello message
        buffer[0] = OP_LOGIN;
        copy(username.begin(), username.end(), buffer.begin() + 1);
        copy(nonceClient.begin(), nonceClient.end(), buffer.begin() + 1 + username.length());
        socketClient.sendMessage(socketClient.getMasterFD(), buffer.data(), username.length() + NONCE_SIZE + 1);

        // Receive server hello
        messageReceivedLen = socketClient.receiveMessage(socketClient.getMasterFD(), buffer.data());

        plaintext = new (nothrow) unsigned char[messageReceivedLen];
        if(!plaintext)
            throw runtime_error("An error occurred while allocating the buffer.");
        plainlen = crypto.publicKeyDecryption(buffer.data(), messageReceivedLen,plaintext,prvkey);

        // Check and extract nonce
        if(!equal(plaintext + plainlen-2*NONCE_SIZE, plaintext + plainlen - NONCE_SIZE, nonceClient.begin()))
            throw runtime_error("Login Error: The freshness of the message is not confirmed");

        copy_n(plaintext + plainlen - NONCE_SIZE, NONCE_SIZE, nonceServer.begin());

        // Verify certificate
        crypto.deserializeCertificate(plainlen - 2*NONCE_SIZE, plaintext, cert);
        if(!crypto.verifyCertificate(cert))
            throw runtime_error("Pay attention, server is not authenticated.");
        cout << "Server authenticated." << endl;

        // Send pwd
        sendPassword(nonceServer.data(), password, username, cert);

        delete[] plaintext;
    } catch (const exception &e) {
        if(plaintext != nullptr) delete[] plaintext;
        throw;
    }
}

// ---------- KEY ESTABLISHMENT ---------- //
void keyEstablishment(unsigned int keyPos) {
    EVP_PKEY *prvKeyA = NULL;
    EVP_PKEY *pubKeyB = NULL;
    unsigned char *buffer = NULL;
    unsigned char *secret = NULL;
    unsigned int keyLen;

    try {
        // Generate public key
        crypto.keyGeneration(prvKeyA);

        // Send public key to peer
        buffer = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!buffer)
            throw runtime_error("An error occurred while allocating the buffer.");
        
        keyLen = crypto.serializePublicKey(prvKeyA, buffer);
        socketClient.sendMessage(socketClient.getMasterFD(), buffer, keyLen);

        // Receive peer's public key
        keyLen = socketClient.receiveMessage(socketClient.getMasterFD(), buffer);
        crypto.deserializePublicKey(buffer, keyLen, pubKeyB);

        // Secret derivation
        secret = new (nothrow) unsigned char[DIGEST_LEN];
        if(!secret)
            throw runtime_error("An error occurred while allocating the buffer.");

        crypto.secretDerivation(prvKeyA, pubKeyB, secret);
        crypto.insertKey(secret, keyPos);

        delete[] buffer;
        delete[] secret;    
    } catch(const exception& e) {
        if(buffer != nullptr) delete[] buffer;
        if(secret != nullptr) delete[] secret;
        throw;
    }
}

void sendKey(string username, string password, EVP_PKEY *pubKey, EVP_PKEY *prvKeyDH) {
    unsigned char *buffer = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *encryptBuffer = NULL;
    unsigned int bufferLen;
    unsigned int ciphertextLen;
    unsigned int encryptBufferLen;
    try {
        // Generate public key
        buffer = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!buffer)
            throw runtime_error("An error occurred while allocating the buffer.");

        bufferLen = crypto.serializePublicKey(prvKeyDH, buffer);

        // Encrypting with peer's public key
        ciphertext = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!ciphertext)
            throw runtime_error("An error occurred while allocating the buffer.");

        ciphertextLen = crypto.publicKeyEncryption(buffer, bufferLen, ciphertext, pubKey);

        // Send public key to peer
        crypto.setSessionKey(0);
        encryptBuffer = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!encryptBuffer)
            throw runtime_error("An error occurred while allocating the buffer.");

        encryptBufferLen = crypto.encryptMessage(ciphertext, ciphertextLen, encryptBuffer);

        // Send message to server for forwarding
        socketClient.sendMessage(socketClient.getMasterFD(), encryptBuffer, encryptBufferLen);

        delete[] buffer;
        delete[] ciphertext;
        delete[] encryptBuffer;
    }catch(const exception& e) {
        if(buffer != nullptr) delete[] buffer;
        if(ciphertext != nullptr) delete[] ciphertext;
        if(encryptBuffer != nullptr) delete[] encryptBuffer;
        throw;
    }
}

void receiveKey(string username, string password, EVP_PKEY *prvKeyDH) {
    EVP_PKEY *prvKey = NULL;
    EVP_PKEY *pubKeyDH = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *keyPeerStream = NULL;
    unsigned char *secret = NULL;
    unsigned int ciphertextLen;
    unsigned int plaintextLen;
    unsigned int keyPeerStreamLen;

    try {
        // Receive peer's public key
        ciphertext = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!ciphertext)
            throw runtime_error("An error occurred while allocating the buffer.");

        ciphertextLen = socketClient.receiveMessage(socketClient.getMasterFD(), ciphertext);
        crypto.setSessionKey(0);

        plaintext = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!plaintext)
            throw runtime_error("An error occurred while allocating the buffer.");

        plaintextLen = crypto.decryptMessage(ciphertext, ciphertextLen, plaintext);
        crypto.readPrivateKey(username, password, prvKey);

        keyPeerStream = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!keyPeerStream)
            throw runtime_error("An error occurred while allocating the buffer.");

        keyPeerStreamLen = crypto.publicKeyDecryption(plaintext, plaintextLen, keyPeerStream, prvKey);
        crypto.deserializePublicKey(keyPeerStream, keyPeerStreamLen, pubKeyDH);

        // Secret derivation
        secret = new (nothrow) unsigned char[DIGEST_LEN];
        if (!secret)
            throw runtime_error("An error occurred while allocating the buffer.");

        crypto.secretDerivation(prvKeyDH, pubKeyDH, secret);
        crypto.insertKey(secret, 1);

        delete[] ciphertext;
        delete[] plaintext;
        delete[] keyPeerStream;
        delete[] secret;
    } catch(const exception& e) {
        if(ciphertext != nullptr) delete[] ciphertext;
        if(plaintext != nullptr) delete[] plaintext;
        if(keyPeerStream != nullptr) delete[] keyPeerStream;
        if(secret != nullptr) delete[] secret;
        throw;
    }
}

// ---------- ONLINE USERS UTILITY ---------- //
void askOnlineUserList() {
    const char* plaintext;
    unsigned char *ciphertext;
    unsigned char *buffer;
    unsigned int ciphertextLen;
    unsigned int plaintextLen;

    try {
        plaintextLen = 25;
        plaintext = "Send me the online users";

        ciphertext = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!ciphertext)
            throw runtime_error("An error occurred while allocating the buffer.");

        crypto.setSessionKey(0);
        ciphertextLen = crypto.encryptMessage((unsigned char*)plaintext, plaintextLen, ciphertext);
        
        buffer = new (nothrow) unsigned char[ciphertextLen + 1];
        if(!buffer)
            throw runtime_error("An error occurred while allocating the buffer.");

        memcpy(buffer, OP_ONLINE_USERS, 1);
        memcpy(buffer + 1, ciphertext, ciphertextLen);
        socketClient.sendMessage(socketClient.getMasterFD(), buffer, ciphertextLen+1);

        delete[] ciphertext;
        delete[] buffer;
    } catch(const exception& e) {
        if(ciphertext != nullptr) delete[] ciphertext;
        if(buffer != nullptr) delete[] buffer;
        throw;
    }
}

bool checkUserOnline(string username, vector<string> onlineUsers) {
    for (string value : onlineUsers) {
        if (value.compare(username) == 0) {
            return true;
        }
    }
    return false;
}

void receiveOnlineUsersList(vector<string> &onlineUsers) {
    unsigned char *buffer; 
    unsigned char *plaintext;
    unsigned int bufferLen;
    unsigned int plaintextLen;
    string usersString;
    string delimiter;
    string token;
    size_t pos;

    try {
        buffer = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!buffer)
            throw runtime_error("An error occurred while allocating the buffer.");

        bufferLen = socketClient.receiveMessage(socketClient.getMasterFD(), buffer);

        plaintext = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!plaintext)
            throw runtime_error("An error occurred while allocating the buffer.");

        plaintextLen = crypto.decryptMessage(buffer, bufferLen, plaintext);
        plaintext[plaintextLen] = '\0';
        usersString = string((const char*) plaintext);

        cout << "Online Users" << endl;

        if (usersString.compare("None") != 0) {
            delimiter = "\n";
            pos = 0;

            while ((pos = usersString.find(delimiter)) != string::npos) {
                token = usersString.substr(0, pos);
                cout << "- " << token << endl;
                onlineUsers.push_back(token);
                usersString.erase(0, pos + delimiter.length());
            }

        } else {
            cout << "** No other users online" << endl;
            onlineUsers.clear();
        }
        
    } catch(const exception& e) {
        if (buffer != nullptr) delete[] buffer;
        if (plaintext != nullptr) delete[] plaintext;
        throw;
    }
}

// ---------- REQUEST TO TALK ---------- //
void requestToTalkInit(unsigned char *nonce, string username) {
    unsigned char *message;
    unsigned char *encryptedMessage;
    unsigned int messageLen;
    unsigned int encryptedMessageLen;
    unsigned int start = 0;

    try {
        message = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!message)
            throw runtime_error("An error occurred while allocating the buffer.");

        crypto.generateNonce(nonce);

        memcpy(message, (const char *)username.c_str(), username.length());
        start += username.length();
        memcpy(message + start, nonce, NONCE_SIZE);
        messageLen = NONCE_SIZE + username.length();

        encryptedMessage = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!encryptedMessage)
            throw runtime_error("An error occurred while allocating the buffer.");

        crypto.setSessionKey(0);
        encryptedMessageLen = crypto.encryptMessage(message, messageLen, encryptedMessage);

        memcpy(message, OP_REQUEST_TO_TALK, 1);
        start = 1;
        memcpy(message + start, encryptedMessage, encryptedMessageLen);
        messageLen = encryptedMessageLen + 1;

        socketClient.sendMessage(socketClient.getMasterFD(), message, messageLen);

        delete[] message;
        delete[] encryptedMessage;
    } catch(const exception& e) {
        if (message != nullptr) delete[] message;
        if (encryptedMessage != nullptr) delete[] encryptedMessage;
        throw;
    }
}

uint64_t extractNoncesCiphertextLength(unsigned char *buffer, unsigned int bufferLen) {
    uint64_t value;
    memcpy(&value, buffer,sizeof(uint64_t));
    return value;
}

void extractPubKeyB(EVP_PKEY *&pubKeyB, unsigned char *nonce, unsigned char *nonceB, string username, string password) {
    EVP_PKEY *prvKeyA;
    unsigned char *ciphertext = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *pubKeyBBuff = NULL;
    unsigned char *nonceAreceived = NULL;
    unsigned char *encryptedNonces = NULL;
    unsigned char *noncesPt = NULL;
    unsigned int plaintextLen;
    unsigned int ciphertextLen;
    unsigned int encryptedNoncesLen;
    unsigned int pubKeyBLen;
    unsigned int start = 0;
    unsigned int headerLen = 10; // "OK" + 8 bytes

    try {
        ciphertext = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!ciphertext)
            throw runtime_error("An error occurred while allocating the buffer.");
        
        ciphertextLen = socketClient.receiveMessage(socketClient.getMasterFD(), ciphertext);

        plaintext = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!plaintext)
            throw runtime_error("An error occurred while allocating the buffer.");
        
        plaintextLen = crypto.decryptMessage(ciphertext, ciphertextLen, plaintext);
        encryptedNoncesLen = extractNoncesCiphertextLength(plaintext, plaintextLen);

        if(memcmp(plaintext + sizeof(uint64_t), "OK", 2) != 0) {
            throw runtime_error("Request to talk operation not successful: OK is missing (error occurred receiving M4 of the protocol).");
        }

        encryptedNonces = new (nothrow) unsigned char[encryptedNoncesLen];
        if(!encryptedNonces)
            throw runtime_error("An error occurred while allocating the buffer.");

        start += headerLen;
        memcpy(encryptedNonces, plaintext + start, encryptedNoncesLen);
        pubKeyBLen = plaintextLen - encryptedNoncesLen - headerLen; 

        pubKeyBBuff = new (nothrow) unsigned char[pubKeyBLen];
        if(!pubKeyBBuff)
            throw runtime_error("An error occurred while allocating the buffer.");

        start = headerLen + encryptedNoncesLen;
        memcpy(pubKeyBBuff, plaintext + start, pubKeyBLen);
        crypto.deserializePublicKey(pubKeyBBuff, pubKeyBLen, pubKeyB);

        nonceAreceived = new (nothrow) unsigned char[NONCE_SIZE];
        if(!nonceAreceived)
            throw runtime_error("An error occurred while allocating the buffer.");

        crypto.readPrivateKey(username, password, prvKeyA);
        
        noncesPt = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!noncesPt)
            throw runtime_error("An error occurred while allocating the buffer.");

        crypto.publicKeyDecryption(encryptedNonces, encryptedNoncesLen, noncesPt, prvKeyA);
        memcpy(nonceAreceived, noncesPt, NONCE_SIZE);

        if(memcmp(nonce, nonceAreceived, NONCE_SIZE) != 0)
            throw runtime_error("Request to talk operation not successful: nonce are different, the message is not fresh (error occurred receiving M4 of the protocol).");

        memcpy(nonceB, noncesPt+NONCE_SIZE, NONCE_SIZE);

        delete[] ciphertext;
        delete[] plaintext;
        delete[] encryptedNonces;
        delete[] nonceAreceived;
        delete[] noncesPt;
    } catch(const exception& e) {
        if(ciphertext != nullptr) delete[] ciphertext;
        if(plaintext != nullptr) delete[] plaintext;
        if(encryptedNonces != nullptr) delete[] encryptedNonces;
        if(nonceAreceived != nullptr) delete[] nonceAreceived;
        if(noncesPt != nullptr) delete[] noncesPt;
        throw;
    }
}

void sendNoncesToB(EVP_PKEY* pubKeyB, unsigned char *nonce, unsigned char *nonceB) {
    unsigned char *ciphertext = NULL;
    unsigned char *nonces = NULL;
    unsigned char *message = NULL;
    unsigned int messageLen;
    unsigned int ciphertextLen;
    unsigned int start = 0;

    try {
        ciphertext = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!ciphertext)
            throw runtime_error("An error occurred while allocating the buffer.");
            
        nonces = new (nothrow) unsigned char[NONCE_SIZE*2];
        if(!nonces)
            throw runtime_error("An error occurred while allocating the buffer.");

        memcpy(nonces, nonce, NONCE_SIZE);
        memcpy(nonces + NONCE_SIZE, nonceB, NONCE_SIZE);
        ciphertextLen = crypto.publicKeyEncryption(nonces, NONCE_SIZE*2, ciphertext, pubKeyB);

        messageLen = ciphertextLen + 2;
        message = new (nothrow) unsigned char[ciphertextLen + 2];
        if(!message)
            throw runtime_error("An error occurred while allocating the buffer.");

        memcpy(message, "OK", 2);
        start += 2;
        memcpy(message + 2, ciphertext, ciphertextLen);
        ciphertextLen = crypto.encryptMessage(message, messageLen, ciphertext);
        socketClient.sendMessage(socketClient.getMasterFD(), ciphertext, ciphertextLen);

        delete[] ciphertext;
        delete[] nonces;
        delete[] message;
    } catch(const exception& e) {
        if (ciphertext != nullptr) delete[] ciphertext;
        if (nonces != nullptr) delete[] nonces;
        if (message != nullptr) delete[] message;
        throw;
    }
}

void finalizeRequestToTalk() {
    unsigned char *ciphertext = NULL;
    unsigned char *plaintext = NULL;
    unsigned int plaintextLen;
    unsigned int ciphertextLen;

    try {
        ciphertext = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!ciphertext)
            throw runtime_error("An error occurred while allocating the buffer.");

        ciphertextLen = socketClient.receiveMessage(socketClient.getMasterFD(), ciphertext);
        
        plaintext = new (nothrow) unsigned char[ciphertextLen];
        if(!plaintext)
            throw runtime_error("An error occurred while allocating the buffer.");

        plaintextLen = crypto.decryptMessage(ciphertext, ciphertextLen, plaintext);

        if(memcmp(plaintext, "OK", 2) != 0) {
            throw runtime_error("Request to talk operation not successful: error occurred receiving M8 of the protocol");
        }

        delete[] ciphertext;
        delete[] plaintext;
    } catch(const exception& e) {
        if(ciphertext != nullptr) delete[] ciphertext;
        if(plaintext != nullptr) delete[] plaintext;
        throw;
    }
}

void extractPubKeyA(unsigned char *nonceA, string &peerAUsername, EVP_PKEY *&pubKeyA) {
    unsigned char *ciphertext = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *keyBuffer = NULL;
    unsigned char *peerAUsr = NULL;
    unsigned int ciphertextLen;
    unsigned int plaintextLen;
    unsigned int keyBufferLen;
    unsigned int start = 0;
    uint64_t peerALen;

    try {
        ciphertext = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!ciphertext)
            throw runtime_error("An error occurred while allocating the buffer.");

        ciphertextLen = socketClient.receiveMessage(socketClient.getMasterFD(), ciphertext);

        if(memcmp(ciphertext, OP_REQUEST_TO_TALK, 1) != 0) {
            throw runtime_error("Request to talk operation not successful: wrong OP");
        }

        plaintext = new (nothrow) unsigned char[ciphertextLen-1];
        if(!plaintext)
            throw runtime_error("An error occurred while allocating the buffer.");

        crypto.setSessionKey(0);
        plaintextLen = crypto.decryptMessage(ciphertext+1, ciphertextLen-1, plaintext);
        
        memcpy(&peerALen, plaintext, sizeof(uint64_t));
        start += sizeof(uint64_t);

        peerAUsr = new (nothrow) unsigned char[peerALen];
        if(!peerAUsr)
            throw runtime_error("An error occurred while allocating the buffer.");

        memcpy(peerAUsr, plaintext + start, peerALen);
        start += peerALen;
        peerAUsername = string((const char*)peerAUsr);
        keyBufferLen = plaintextLen - NONCE_SIZE - peerALen - sizeof(uint64_t);

        keyBuffer = new (nothrow) unsigned char[keyBufferLen];
        if(!keyBuffer)
            throw runtime_error("An error occurred while allocating the buffer.");

        memcpy(keyBuffer, plaintext + start, keyBufferLen);
        crypto.deserializePublicKey(keyBuffer, keyBufferLen, pubKeyA);
        start += keyBufferLen;
        memcpy(nonceA, plaintext+start, NONCE_SIZE);

        delete[] ciphertext;
        delete[] plaintext;
        delete[] peerAUsr;
        delete[] keyBuffer;
    } catch(const exception& e) {
        if (ciphertext != nullptr) delete[] ciphertext;
        if (plaintext != nullptr) delete[] plaintext;
        if (peerAUsr != nullptr) delete[] peerAUsr;
        if (keyBuffer != nullptr) delete[] keyBuffer;
        throw;
    }
}

void sendNoncesToA(unsigned char *nonce, unsigned char *nonceA, EVP_PKEY *pubKeyA) {
    unsigned char *plaintext = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *noncesCT = NULL;
    unsigned char *noncesPT = NULL;
    unsigned int plaintextLen;
    unsigned int ciphertextLen;
    unsigned int noncesCTLen;
    unsigned int noncesPTLen = 2*NONCE_SIZE;

    try {
        crypto.generateNonce(nonce);

        noncesPT = new (nothrow)  unsigned char[noncesPTLen];
        if(!noncesPT)
            throw runtime_error("An error occurred while allocating the buffer.");

        memcpy(noncesPT, nonceA, NONCE_SIZE);
        memcpy(noncesPT + NONCE_SIZE, nonce, NONCE_SIZE);

        noncesCT = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!noncesCT)
            throw runtime_error("An error occurred while allocating the buffer.");

        noncesCTLen = crypto.publicKeyEncryption(noncesPT, noncesPTLen, noncesCT, pubKeyA);
        plaintextLen = noncesCTLen + 2;

        plaintext = new (nothrow) unsigned char[plaintextLen];
        if(!plaintext)
            throw runtime_error("An error occurred while allocating the buffer.");

        memcpy(plaintext, "OK", 2);
        memcpy(plaintext + 2, noncesCT, noncesCTLen);

        ciphertext = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!ciphertext)
            throw runtime_error("An error occurred while allocating the buffer.");
        
        crypto.setSessionKey(0);
        ciphertextLen = crypto.encryptMessage(plaintext, plaintextLen, ciphertext);
        socketClient.sendMessage(socketClient.getMasterFD(), ciphertext, ciphertextLen);

        delete[] noncesPT;
        delete[] noncesCT;
        delete[] plaintext;
        delete[] ciphertext;
    } catch(const exception& e) {
        if(noncesPT != nullptr) delete[] noncesPT;
        if(noncesCT != nullptr) delete[] noncesCT;
        if(plaintext != nullptr) delete[] plaintext;
        if(ciphertext != nullptr) delete[] ciphertext;
        throw;
    }   
}

void refuseRequestToTalk() {
    unsigned char plaintext[2];
    unsigned char *ciphertext = NULL;
    unsigned int plaintextLen = 2;
    unsigned int ciphertextLen;

    try {
        memcpy(plaintext, "NO", 2);
        crypto.setSessionKey(0);

        ciphertext = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!ciphertext)
            throw runtime_error("An error occurred while allocating the buffer.");

        ciphertextLen = crypto.encryptMessage(plaintext, plaintextLen, ciphertext);
        socketClient.sendMessage(socketClient.getMasterFD(), ciphertext, ciphertextLen);

        delete[] ciphertext;
    } catch(const exception& e) {
        if(ciphertext != nullptr) delete[] ciphertext;
        throw;
    }
}

void validateFreshness(unsigned char* nonce, string username, string password) {
    EVP_PKEY *prvKeyB;
    unsigned char *plaintext = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *noncesPT = NULL;
    unsigned char *noncesCT = NULL;
    unsigned char *nonceReceivedB = NULL;
    unsigned int plaintextLen;
    unsigned int ciphertextLen;
    unsigned int noncesPTLen;
    unsigned int noncesCTLen;
    
    try {
        ciphertext = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!ciphertext)
            throw runtime_error("An error occurred while allocating the buffer.");

        ciphertextLen = socketClient.receiveMessage(socketClient.getMasterFD(), ciphertext);

        plaintext = new (nothrow) unsigned char[ciphertextLen];
        if(!plaintext)
            throw runtime_error("An error occurred while allocating the buffer.");

        crypto.setSessionKey(0);
        plaintextLen = crypto.decryptMessage(ciphertext, ciphertextLen, plaintext);

        if(memcmp(plaintext, "OK", 2) != 0)
            throw runtime_error("Request to talk operation not successful: wrong OP (error occurred receiving M6)");

        crypto.readPrivateKey(username, password, prvKeyB);
        noncesCTLen = plaintextLen-2;

        noncesCT = new (nothrow) unsigned char[noncesCTLen];
        if(!noncesCT)
            throw runtime_error("An error occurred while allocating the buffer.");

        memcpy(noncesCT, plaintext+2, noncesCTLen);

        noncesPT = new unsigned char[MAX_MESSAGE_SIZE];
        if(!noncesPT)
            throw runtime_error("An error occurred while allocating the buffer.");

        noncesPTLen = crypto.publicKeyDecryption(noncesCT, noncesCTLen, noncesPT, prvKeyB);

        nonceReceivedB = new unsigned char[NONCE_SIZE];
        if(!nonceReceivedB)
            throw runtime_error("An error occurred while allocating the buffer.");

        memcpy(nonceReceivedB, noncesPT+NONCE_SIZE, NONCE_SIZE);

        if(memcmp(nonceReceivedB, nonce, NONCE_SIZE) != 0)
            throw runtime_error("Request to talk operation not successful: nonce are different, the message is not fresh (error occurred receiving M6).");

        delete[] ciphertext;
        delete[] plaintext;
        delete[] noncesCT;
        delete[] noncesPT;
        delete[] nonceReceivedB;
    } catch(const exception& e) {
        if(ciphertext != nullptr) delete[] ciphertext;
        if(plaintext != nullptr) delete[] plaintext;
        if(noncesCT != nullptr) delete[] noncesCT;
        if(noncesPT != nullptr) delete[] noncesPT;
        if(nonceReceivedB != nullptr) delete[] nonceReceivedB;
        throw;
    }
    
}

void sendOkMessage() {
    unsigned char *ciphertext = NULL;
    unsigned char *plaintext = NULL;
    unsigned int ciphertextLen;
    unsigned int plaintextLen = 2;

    try {
        plaintext = new (nothrow) unsigned char[plaintextLen];
        if(!plaintext)
            throw runtime_error("An error occurred while allocating the buffer.");

        memcpy(plaintext, "OK", 2);
        crypto.setSessionKey(0);

        ciphertext = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!ciphertext)
            throw runtime_error("An error occurred while allocating the buffer.");

        ciphertextLen = crypto.encryptMessage(plaintext, 2, ciphertext);
        socketClient.sendMessage(socketClient.getMasterFD(), ciphertext, ciphertextLen);

        delete[] plaintext;
        delete[] ciphertext;
    } catch(const std::exception& e) {
        if (plaintext != nullptr) delete[] plaintext;
        if (ciphertext != nullptr) delete[] ciphertext;
        throw;
    }
}

void sendRequestToTalk(string usernameReceiver, string usernameSender, string password) {
    unsigned char *nonce = NULL;
    unsigned char *nonceB = NULL;
    EVP_PKEY *pubKeyB = NULL;
    EVP_PKEY *prvKeyDH = NULL;

    try {
        // Send Message M1
        nonce = new (nothrow) unsigned char[NONCE_SIZE];
        if(!nonce)
            throw runtime_error("An error occurred while allocating the buffer.");

        requestToTalkInit(nonce, usernameReceiver);
        cout << "\nRequest to talk sent to " << usernameReceiver << endl;

        // Receive Message M4:
        nonceB = new (nothrow) unsigned char[NONCE_SIZE];
        if(!nonceB)
            throw runtime_error("An error occurred while allocating the buffer.");

        extractPubKeyB(pubKeyB, nonce, nonceB, usernameSender, password);

        // Send Message M5:
        sendNoncesToB(pubKeyB, nonce, nonceB);

        // Receive Message M8:
        finalizeRequestToTalk();

        cout << "Request to talk accepted by " << usernameReceiver << endl;
        crypto.keyGeneration(prvKeyDH);
        sendKey(usernameSender, password, pubKeyB, prvKeyDH);
        receiveKey(usernameSender, password, prvKeyDH);

        delete[] nonce;
        delete[] nonceB;
    } catch(const exception& e) {
        cout << "Error in send request to talk: " << e.what() << endl;
        if (nonce != nullptr) delete[] nonce;
        if (nonceB != nullptr) delete[] nonceB;
    }
}

void receiveRequestToTalk(string username, string password, string &peerAUsername) {
    string confirmation;
    unsigned char *nonce;
    unsigned char *nonceA;
    EVP_PKEY *pubKeyA = NULL;
    EVP_PKEY *prvKeyDH = NULL;

    try {
        // Receive M2:
        nonceA = new (nothrow) unsigned char[NONCE_SIZE];
        if(!nonceA)
            throw runtime_error("An error occurred while allocating the buffer.");

        extractPubKeyA(nonceA, peerAUsername, pubKeyA);
        cout << peerAUsername << " wants to talk with you" << endl;

        // Send M3:
        nonce = new (nothrow) unsigned char[NONCE_SIZE];
        if(!nonce)
            throw runtime_error("An error occurred while allocating the buffer.");
        
        // Accept
        confirmation = readFromStdout("Type y to accept --> ");
        if (strcasecmp((const char *)confirmation.c_str(), "Y")) {
            cout << "The request to talk has been refused." << endl;
            refuseRequestToTalk();
            delete[] nonceA;
            delete[] nonce;
            return;
        }

        sendNoncesToA(nonce, nonceA, pubKeyA);

        // Receive M6:
        validateFreshness(nonce, username, password);

        // Send M7:
        sendOkMessage();
        crypto.keyGeneration(prvKeyDH);

        //Receive key from A
        receiveKey(username, password, prvKeyDH);
        sendKey(username, password, pubKeyA, prvKeyDH);

        delete[] nonceA;
        delete[] nonce;
    } catch(const exception& e) {
        cout << "Error in receive request to talk: " << e.what() << endl;
        if (nonceA != nullptr) delete[] nonceA;
        if (nonce != nullptr) delete[] nonce;
    }
}

// ---------- MESSAGE UTILITY ---------- //
void sendMessage(string message) {
    unsigned char *ciphertext = NULL;
    unsigned char *serverCT;
    unsigned char *msg;
    unsigned char *buffer;
    unsigned int msgLen;
    unsigned int ciphertextLen;
    unsigned int serverCTLen;

    try {
        msgLen = message.length();
        msg = (unsigned char*)message.c_str();
        if(msgLen > MAX_MESSAGE_SIZE) 
            throw runtime_error("Message size is greater than the maximum");
        
        crypto.setSessionKey(1);
        ciphertext = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!ciphertext)
            throw runtime_error("An error occurred while allocating the buffer.");
        
        ciphertextLen = crypto.encryptMessage(msg, msgLen, ciphertext);
        crypto.setSessionKey(0);

        serverCT = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!serverCT)
            throw runtime_error("An error occurred while allocating the buffer.");

        serverCTLen = crypto.encryptMessage(ciphertext, ciphertextLen, serverCT);
        
        buffer = new (nothrow) unsigned char[serverCTLen+1];
        if(!buffer)
            throw runtime_error("An error occurred while allocating the buffer.");

        memcpy(buffer,OP_MESSAGE,1);
        memcpy(buffer + 1,serverCT,serverCTLen);
        socketClient.sendMessage(socketClient.getMasterFD(), buffer, serverCTLen + 1);

        delete[] ciphertext;
        delete[] serverCT;
        delete[] buffer;
    } catch(const exception& e) {
        if(ciphertext != nullptr) delete[] ciphertext;
        if(serverCT != nullptr) delete[] serverCT;
        if(buffer != nullptr) delete[] buffer;
        throw;
    }
}

string receiveMessage(){
    unsigned char *ciphertext = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *text;
    unsigned int cipherlen;
    unsigned int plainlen;
    unsigned int textLen;

    try {
        ciphertext = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!ciphertext)
            throw runtime_error("An error occurred while allocating the buffer.");

        cipherlen = socketClient.receiveMessage(socketClient.getMasterFD(), ciphertext);
        crypto.setSessionKey(0);

        plaintext = new (nothrow) unsigned char[cipherlen];
        if(!plaintext)
            throw runtime_error("An error occurred while allocating the buffer.");
    
        plainlen = crypto.decryptMessage(ciphertext, cipherlen, plaintext);
        crypto.setSessionKey(1);

        text = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!text)
            throw runtime_error("An error occurred while allocating the buffer.");

        textLen = crypto.decryptMessage(plaintext, plainlen, text);
        text[textLen] = '\0';


        delete[] ciphertext;
        delete[] plaintext;
        delete[] text;
    } catch(const exception& e) {
        if(ciphertext != nullptr) delete[] ciphertext;
        if(plaintext != nullptr) delete[] ciphertext;
        if(text != nullptr) delete[] ciphertext;
        return "";
    }

    return string((const char*)text);  
}

// ---------- CLOSE CONNECTION ---------- //
void sendCloseConnection(string username) {
    string msg;
    unsigned char *ciphertext = NULL;
    unsigned char *serverCT = NULL;
    unsigned char *buffer;
    unsigned int ciphertextLen;
    unsigned int serverCTLen;

    try {
        crypto.setSessionKey(1);
        ciphertext = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!ciphertext)
            throw runtime_error("An error occurred while allocating the buffer.");
        
        msg = "!deh";
        ciphertextLen = crypto.encryptMessage((unsigned char*)msg.c_str(), msg.length(), ciphertext);
        crypto.setSessionKey(0);

        serverCT = new (nothrow) unsigned char[MAX_MESSAGE_SIZE];
        if(!serverCT)
            throw runtime_error("An error occurred while allocating the buffer.");

        serverCTLen = crypto.encryptMessage(ciphertext, ciphertextLen, serverCT);
        
        buffer = new (nothrow) unsigned char[serverCTLen + 1];
        if(!buffer)
            throw runtime_error("An error occurred while allocating the buffer.");

        memcpy(buffer,OP_LOGOUT,1);
        memcpy(buffer + 1,serverCT,serverCTLen);
        socketClient.sendMessage(socketClient.getMasterFD(), buffer, serverCTLen+1);
        crypto.removeKey(1);
        crypto.setSessionKey(0);

        delete[] ciphertext;
        delete[] serverCT;
        delete[] buffer;
    } catch(const exception& e) {
        if(ciphertext != nullptr) delete[] ciphertext;
        if(serverCT != nullptr) delete[] serverCT;
        if(buffer != nullptr) delete[] buffer;
        throw;
    }
}