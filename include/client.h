#include "socket.h"
#include "crypto.h"
#include <iterator>
#include <array>
#include <cstring>
#include <algorithm>
#include <termios.h>

void keyEstablishmentServer(unsigned int keyPos, string username, string password, EVP_PKEY* serverPubKey);

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

void sendPassword(unsigned char *nonce, string password, string username, EVP_PKEY *server_pubkey) {
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
    EVP_PKEY *serverPubKey = NULL;
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
        crypto.getPublicKeyFromCertificate(cert,serverPubKey);
        sendPassword(nonceServer.data(), password, username, serverPubKey);

        //Start Key Establishment
        keyEstablishmentServer(0, username, password, serverPubKey);

        delete[] plaintext;
    } catch (const exception &e) {
        string message = e.what();
        message = "Authentication Error: " + message;
        if(plaintext != nullptr) delete[] plaintext;
        throw runtime_error(message);
    }
}

// ---------- KEY ESTABLISHMENT ---------- //
void keyEstablishmentServer(unsigned int keyPos, string username, string password, EVP_PKEY* serverPubKey) {
    EVP_PKEY *clientPrvKeyDH = NULL;
    EVP_PKEY *clientPubKeyDH = NULL;
    EVP_PKEY *clientPrvKey = NULL;
    array<unsigned char, MAX_MESSAGE_SIZE> ciphertext;
    array<unsigned char, MAX_MESSAGE_SIZE> plaintext;
    unsigned char *secret = NULL;
    unsigned int ciphertextLen;
    unsigned int plaintextLen;

    try {
        // Generate public key
        crypto.keyGeneration(clientPrvKeyDH);
        crypto.readPrivateKey(username, password, clientPrvKey);

        // Send public key to peer
        plaintextLen = crypto.serializePublicKey(clientPrvKeyDH, plaintext.data());
        ciphertextLen = crypto.publicKeyEncryption(plaintext.data(), plaintextLen, ciphertext.data(), serverPubKey);
        socketClient.sendMessage(socketClient.getMasterFD(), ciphertext.data(), ciphertextLen);

        // Receive peer's public key
        ciphertextLen = socketClient.receiveMessage(socketClient.getMasterFD(), ciphertext.data());
        if(ciphertextLen == 0) {
            throw runtime_error("Error receiving the ciphertext of the server PubKey");
        }
        plaintextLen = crypto.publicKeyDecryption(ciphertext.data(), ciphertextLen, plaintext.data(), clientPrvKey);
        crypto.deserializePublicKey(plaintext.data(), plaintextLen, clientPubKeyDH);

        // Secret derivation
        secret = new (nothrow) unsigned char[DIGEST_LEN];

        if(!secret)
            throw runtime_error("An error occurred while allocating the buffer.");

        crypto.secretDerivation(clientPrvKeyDH, clientPubKeyDH, secret);
        crypto.insertKey(secret, keyPos);

        delete[] secret;    
    } catch(const exception& e) {
        string message = e.what();
        message = "Error in the key establishment:\n\t" + message;
        if(secret != nullptr) delete[] secret;
        throw runtime_error(message);
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
void requestToTalkInit(array<unsigned char, NONCE_SIZE> &nonce, string username) {
    array<unsigned char, MAX_MESSAGE_SIZE> message;
    array<unsigned char, MAX_MESSAGE_SIZE> encryptedMessage;
    unsigned int encryptedMessageLen;

    try {
        crypto.generateNonce(nonce.data());

        copy(username.begin(), username.end(), message.begin());
        copy_n(nonce.begin(), NONCE_SIZE, message.begin() + username.length());

        crypto.setSessionKey(0);
        encryptedMessageLen = crypto.encryptMessage(message.data(), NONCE_SIZE + username.length(), encryptedMessage.data());

        copy_n(OP_REQUEST_TO_TALK, 1, message.begin());    
        copy_n(encryptedMessage.begin(), encryptedMessageLen, message.begin() + 1);
        
        socketClient.sendMessage(socketClient.getMasterFD(), message.data(), encryptedMessageLen + 1);
    } catch(const exception& e) {
        throw;
    }
}

void extractPubKeyB(EVP_PKEY *&pubKeyB, array<unsigned char, NONCE_SIZE> nonce, array<unsigned char, NONCE_SIZE> &nonceB, string username, string password) {
    EVP_PKEY *prvKeyA;
    array<unsigned char,MAX_MESSAGE_SIZE> buffer;
    array<unsigned char,MAX_MESSAGE_SIZE> plaintext;
    vector<unsigned char> encryptedNonces;
    unsigned int plaintextLen;
    unsigned int bufferLen;
    unsigned int pubKeyBLen;
    unsigned int headerLen = sizeof(uint64_t) + 2; // "OK" + 8 bytes
    uint64_t encryptedNoncesLen;

    try {
        bufferLen = socketClient.receiveMessage(socketClient.getMasterFD(), buffer.data());
        plaintextLen = crypto.decryptMessage(buffer.data(), bufferLen, plaintext.data());

        if(equal(plaintext.begin(), plaintext.begin() + 2, "OK")) {
            memcpy(&encryptedNoncesLen, plaintext.data() + 2, sizeof(uint64_t));
            encryptedNonces.insert(encryptedNonces.end(), plaintext.begin() + headerLen, plaintext.begin() + headerLen + encryptedNoncesLen);
            crypto.readPrivateKey(username, password, prvKeyA);
            crypto.publicKeyDecryption(encryptedNonces.data(), encryptedNoncesLen, buffer.data(), prvKeyA);
        
            if(!equal(buffer.begin(), buffer.begin() + NONCE_SIZE, nonce.begin()))
                throw runtime_error("Request to talk operation not successful: nonce are different, the message is not fresh (error occurred receiving M4 of the protocol).");
        
            copy(buffer.begin() + NONCE_SIZE, buffer.begin() + 2*NONCE_SIZE, nonceB.begin());
            copy(plaintext.begin() + headerLen + encryptedNoncesLen, plaintext.begin() + plaintextLen, buffer.begin());
            pubKeyBLen = plaintextLen - headerLen - encryptedNoncesLen;
            crypto.deserializePublicKey(buffer.data(), pubKeyBLen, pubKeyB);
            
        } else if(equal(plaintext.begin(), plaintext.begin() + 2, "NO")) {
            cout << "Request to talk refused." << endl;
            return;
        } else {
            throw runtime_error("Request to talk operation not successful: OK is missing (error occurred receiving M4 of the protocol).");
        }

    } catch(const exception& e) {
        throw;
    }
}

void sendNoncesToB(EVP_PKEY* pubKeyB, array<unsigned char,NONCE_SIZE> nonceB) {
    array<unsigned char, MAX_MESSAGE_SIZE> ciphertext;
    array<unsigned char, MAX_MESSAGE_SIZE> message;
    unsigned int ciphertextLen;

    try {            

        ciphertextLen = crypto.publicKeyEncryption(nonceB.data(), NONCE_SIZE, ciphertext.data(), pubKeyB);
        copy_n("OK", 2, message.begin());
        copy_n(ciphertext.begin(), ciphertextLen, message.begin() + 2);

        ciphertextLen = crypto.encryptMessage(message.data(), ciphertextLen + 2, ciphertext.data());
        socketClient.sendMessage(socketClient.getMasterFD(), ciphertext.data(), ciphertextLen);
    } catch(const exception& e) {
        throw;
    }
}

void finalizeRequestToTalk() {
    array<unsigned char, MAX_MESSAGE_SIZE> ciphertext;
    array<unsigned char, MAX_MESSAGE_SIZE> plaintext;
    unsigned int plaintextLen;
    unsigned int ciphertextLen;

    try {
        ciphertextLen = socketClient.receiveMessage(socketClient.getMasterFD(), ciphertext.data());
        plaintextLen = crypto.decryptMessage(ciphertext.data(), ciphertextLen, plaintext.data());

        if(!equal(plaintext.begin(), plaintext.begin() + 2, "OK")) {
            throw runtime_error("Request to talk operation not successful: error occurred receiving M8 of the protocol");
        }

    } catch(const exception& e) {
        throw;
    }
}

void extractPubKeyA(array<unsigned char, NONCE_SIZE> &nonceA, string &peerAUsername, EVP_PKEY *&pubKeyA) {
    array <unsigned char, MAX_MESSAGE_SIZE> ciphertext;
    array <unsigned char, MAX_MESSAGE_SIZE> plaintext;
    unsigned int ciphertextLen;
    unsigned int plaintextLen;
    unsigned int keyBufferLen;
    uint64_t peerALen;

    try {
        ciphertextLen = socketClient.receiveMessage(socketClient.getMasterFD(), ciphertext.data());

        if(!equal(ciphertext.begin(), ciphertext.begin() + 1, OP_REQUEST_TO_TALK)) {
            throw runtime_error("Request to talk operation not successful: wrong OP");
        }

        crypto.setSessionKey(0);
        plaintextLen = crypto.decryptMessage(ciphertext.data() + 1, ciphertextLen-1, plaintext.data()); 

        memcpy(&peerALen, plaintext.data(), sizeof(uint64_t));

        peerAUsername = string(plaintext.begin() + sizeof(uint64_t), plaintext.begin() + sizeof(uint64_t) + peerALen);
        keyBufferLen = plaintextLen - NONCE_SIZE - peerALen - sizeof(uint64_t);

        copy_n(plaintext.begin() + sizeof(uint64_t) + peerALen, keyBufferLen, ciphertext.data());
        crypto.deserializePublicKey(ciphertext.data(), keyBufferLen, pubKeyA);

        copy_n(plaintext.begin() + sizeof(uint64_t) + peerALen + keyBufferLen, NONCE_SIZE, nonceA.data());
    } catch(const exception& e) {
        throw;
    }
}

void sendNoncesToA(array<unsigned char, NONCE_SIZE> &nonce, array<unsigned char, NONCE_SIZE> nonceA, EVP_PKEY *pubKeyA) {
    array<unsigned char, MAX_MESSAGE_SIZE> plaintext;
    array<unsigned char, MAX_MESSAGE_SIZE> ciphertext;
    unsigned int ciphertextLen;
    uint64_t noncesLen;
    
    try {
        crypto.generateNonce(nonce.data());

        copy_n(nonceA.begin(), NONCE_SIZE, plaintext.data());
        copy_n(nonce.begin(), NONCE_SIZE, plaintext.data() + NONCE_SIZE);

        noncesLen = crypto.publicKeyEncryption(plaintext.data(), 2 * NONCE_SIZE, ciphertext.data(), pubKeyA);
        
        copy_n("OK", 2, plaintext.data());
        memcpy(plaintext.data() + 2, &noncesLen, sizeof(uint64_t));
        copy_n(ciphertext.begin(), noncesLen, plaintext.data() + 2 + sizeof(uint64_t));
        
        crypto.setSessionKey(0);
        ciphertextLen = crypto.encryptMessage(plaintext.data(), 2 + sizeof(uint64_t) + noncesLen, ciphertext.data());
        socketClient.sendMessage(socketClient.getMasterFD(), ciphertext.data(), ciphertextLen);
    } catch(const exception& e) {
        throw;
    }   
}

void refuseRequestToTalk() {
    array<unsigned char, 2> plaintext;
    array<unsigned char, MAX_MESSAGE_SIZE> ciphertext;
    unsigned int ciphertextLen;

    try {

        copy_n("NO", 2, plaintext.data());
        crypto.setSessionKey(0);
        ciphertextLen = crypto.encryptMessage(plaintext.data(), 2, ciphertext.data());
        socketClient.sendMessage(socketClient.getMasterFD(), ciphertext.data(), ciphertextLen);

    } catch(const exception& e) {
        throw;
    }
}

void validateFreshness(array<unsigned char, NONCE_SIZE> nonce, string username, string password) {
    EVP_PKEY *prvKeyB;
    array<unsigned char, MAX_MESSAGE_SIZE> ciphertext;
    array<unsigned char, MAX_MESSAGE_SIZE> plaintext;
    unsigned int plaintextLen;
    unsigned int ciphertextLen;
    
    try {
        ciphertextLen = socketClient.receiveMessage(socketClient.getMasterFD(), ciphertext.data());
        crypto.setSessionKey(0);
        plaintextLen = crypto.decryptMessage(ciphertext.data(), ciphertextLen, plaintext.data());

        if(!equal(plaintext.begin(), plaintext.begin() + 2, "OK")) 
            throw runtime_error("Request to talk operation not successful: wrong OP (error occurred receiving M6)");

        crypto.readPrivateKey(username, password, prvKeyB);
        ciphertextLen = crypto.publicKeyDecryption(plaintext.begin() + 2, plaintextLen - 2, ciphertext.data(), prvKeyB);

        if(!equal(ciphertext.begin(), ciphertext.begin() + NONCE_SIZE, nonce.begin()))
            throw runtime_error("Request to talk operation not successful: nonce are different, the message is not fresh (error occurred receiving M6).");
    } catch(const exception& e) {
        throw;
    }   
}

void sendOkMessage() {
    array<unsigned char, MAX_MESSAGE_SIZE> ciphertext;
    array<unsigned char, 2> plaintext;
    unsigned int ciphertextLen;

    try {
        copy_n("OK", 2, plaintext.data());
        crypto.setSessionKey(0);
        ciphertextLen = crypto.encryptMessage(plaintext.data(), 2, ciphertext.data());
        socketClient.sendMessage(socketClient.getMasterFD(), ciphertext.data(), ciphertextLen);
    } catch(const exception& e) {
        throw;
    }
}

void sendRequestToTalk(string usernameReceiver, string usernameSender, string password) {
    array<unsigned char, NONCE_SIZE> nonce;
    array<unsigned char, NONCE_SIZE> nonceB;
    EVP_PKEY *pubKeyB = NULL;
    EVP_PKEY *prvKeyDH = NULL;

    try {
        // Send Message M1
        requestToTalkInit(nonce, usernameReceiver);
        cout << "\nRequest to talk sent to " << usernameReceiver << endl;

        // Receive Message M4:
        extractPubKeyB(pubKeyB, nonce, nonceB, usernameSender, password);

        // Send Message M5:
        sendNoncesToB(pubKeyB, nonceB);

        // Receive Message M8:
        finalizeRequestToTalk();

        cout << "Request to talk accepted by " << usernameReceiver << endl;
        crypto.keyGeneration(prvKeyDH);
        sendKey(usernameSender, password, pubKeyB, prvKeyDH);
        receiveKey(usernameSender, password, prvKeyDH);
    } catch(const exception& e) {
        cout << "Error in send request to talk: " << e.what() << endl;
        throw;
    }
}

void receiveRequestToTalk(string username, string password, string &peerAUsername) {
    string confirmation;
    array<unsigned char, NONCE_SIZE> nonce;
    array<unsigned char, NONCE_SIZE> nonceA;
    EVP_PKEY *pubKeyA = NULL;
    EVP_PKEY *prvKeyDH = NULL;

    try {
        // Receive M2:
        extractPubKeyA(nonceA, peerAUsername, pubKeyA);
        cout << peerAUsername << " wants to talk with you" << endl;

        // Send M3:
        // Accept
        confirmation = readFromStdout("Type y to accept --> ");
        if (strcasecmp((const char *)confirmation.c_str(), "Y")) {
            cout << "The request to talk has been refused." << endl;
            refuseRequestToTalk();
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
        
    } catch(const exception& e) {
        cout << "Error in receive request to talk: " << e.what() << endl;
    }
}

// ---------- MESSAGE UTILITY ---------- //
void sendMessage(string message) {
    array<unsigned char, MAX_MESSAGE_SIZE> ciphertext;
    array<unsigned char, MAX_MESSAGE_SIZE> buffer;
    unsigned int ciphertextLen;
    unsigned int bufferLen;

    try {
        if(message.length() > MAX_MESSAGE_SIZE) 
            throw runtime_error("Message size is greater than the maximum");
        
        crypto.setSessionKey(CLIENT_SECRET);        
        ciphertextLen = crypto.encryptMessage((unsigned char*)message.c_str(), message.length(), ciphertext.data());
        crypto.setSessionKey(SERVER_SECRET);

        bufferLen = crypto.encryptMessage(ciphertext.data(), ciphertextLen, buffer.data());
        copy_n(OP_MESSAGE, 1, ciphertext.data());
        copy_n(buffer.begin(), bufferLen, ciphertext.data() + 1);

        socketClient.sendMessage(socketClient.getMasterFD(), ciphertext.data(), bufferLen + 1);
    } catch(const exception& e) {
        throw;
    }
}

string receiveMessage(){
    array<unsigned char, MAX_MESSAGE_SIZE> ciphertext;
    array<unsigned char, MAX_MESSAGE_SIZE> plaintext;
    unsigned int cipherlen;
    unsigned int plainlen;

    try {
        cipherlen = socketClient.receiveMessage(socketClient.getMasterFD(), ciphertext.data());
        
        crypto.setSessionKey(SERVER_SECRET);
        plainlen = crypto.decryptMessage(ciphertext.data(), cipherlen, plaintext.data());
        
        crypto.setSessionKey(CLIENT_SECRET);

        cipherlen = crypto.decryptMessage(plaintext.data(), plainlen, ciphertext.data());
        ciphertext[cipherlen] = '\0';
        
    } catch(const exception& e) {
        return "";
    }

    return string((const char*)ciphertext.data());  
}

// ---------- CLOSE CONNECTION ---------- //
void sendCloseConnection(string username) {
    string msg;
    array<unsigned char, MAX_MESSAGE_SIZE> ciphertext;
    array<unsigned char, MAX_MESSAGE_SIZE> buffer;
    unsigned int ciphertextLen;
    unsigned int bufferLen;

    try {
        crypto.setSessionKey(CLIENT_SECRET);        
        msg = "!deh";
        ciphertextLen = crypto.encryptMessage((unsigned char*)msg.c_str(), msg.length(), ciphertext.data());
        
        crypto.setSessionKey(SERVER_SECRET);
        bufferLen = crypto.encryptMessage(ciphertext.data(), ciphertextLen, buffer.data());

        copy_n(OP_LOGOUT, 1, ciphertext.data());
        copy_n(buffer.data(), bufferLen, ciphertext.data() + 1);
        socketClient.sendMessage(socketClient.getMasterFD(), ciphertext.data(), bufferLen + 1);
        
        crypto.removeKey(CLIENT_SECRET);
        crypto.setSessionKey(SERVER_SECRET);
    } catch(const exception& e) {
        throw;
    }
}