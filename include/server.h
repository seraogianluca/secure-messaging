#include <fstream>
#include <sstream>
#include <fstream>
#include <iterator>
#include <vector>
#include "crypto.h"
#include "socket.h"


struct onlineUser {
    string username;
    int sd;
    unsigned int key_pos;
};

struct activeChat {
    onlineUser a;
    onlineUser b;
};

SocketServer serverSocket(SOCK_STREAM); //TCP
Crypto crypto(MAX_CLIENTS);

int getOperationCode(unsigned char* message) {
    int opCode = message[0] - '0';
    if (opCode < 0 || opCode > 4) { throw runtime_error("Operation Code not valid");}
    return opCode;
}

unsigned int readPassword(unsigned char* username, unsigned int usernameLen, unsigned char* password) {

    ifstream file("./resources/credentials.txt");
    string line;
    string delimiter = " ";
    string pwd;
    string usn;
    const char* usernameChar = (const char*) username;
    
    while (getline(file, line)) {
        usn = line.substr(0, line.find(delimiter));
        if(usn.compare(usernameChar) == 0) {
            pwd = line.substr(line.find(delimiter) + 1);
            for (int i = 0; i < pwd.length()/2; i++) {
                string substr = pwd.substr(i*2, 2);
                unsigned char v = stoi(substr, 0, 16);
                password[i] = v;
            }
            return pwd.length()/2;
        }
    }
    return 0;
}

void buildHelloMessage(int sd, unsigned char *nonceClient, unsigned char *nonceServer){
    unsigned char *helloMessage = NULL;
    unsigned int start;
    try{
        helloMessage = new unsigned char[5 + 2*NONCE_SIZE];
        start = 0;
        memcpy(helloMessage, "hello", 5);
        start += 5;
        memcpy(helloMessage+start, nonceClient, NONCE_SIZE);
        start += NONCE_SIZE;
        memcpy(helloMessage+start, nonceServer, NONCE_SIZE);
        serverSocket.sendMessage(sd, helloMessage, (5 + 2*NONCE_SIZE));
    }catch(const exception& e) {
        delete[] helloMessage;
        throw;
    }
    delete[] helloMessage;
}

void checkNonce(unsigned char *certificateRequest, unsigned char *nonceServer){
    unsigned char *nonceServerReceived = NULL;
    try{       
        nonceServerReceived = new unsigned char[NONCE_SIZE];
        memcpy(nonceServerReceived, certificateRequest, NONCE_SIZE);

        if(memcmp(nonceServerReceived, nonceServer, NONCE_SIZE) != 0) {
            throw runtime_error("Login Error: The freshness of the message is not confirmed");
        }
    }catch(const exception& e) {
        delete[] nonceServerReceived;
        throw;
    }
    delete[] nonceServerReceived;
}

void sendCertificate(int sd, unsigned char* username, unsigned int usernameLen, unsigned char *nonceClient, unsigned char *nonceServer){
    unsigned char *cert_buff = NULL;
    unsigned char *buffer = NULL;
    unsigned char *encrypt_msg = NULL;
    X509 *cert = NULL;
    EVP_PKEY *user_pubkey = NULL;
    unsigned int cert_len;
    unsigned int start = 0;
    unsigned int bufferLen = 0;
    unsigned int encrypted_msg_len;
    try{
        crypto.loadCertificate(cert,"server_cert");
        cert_buff = new unsigned char[MAX_MESSAGE_SIZE];
        cert_len = crypto.serializeCertificate(cert,cert_buff);

        bufferLen = usernameLen + cert_len + 2*NONCE_SIZE;
        buffer = new unsigned char[bufferLen];
        encrypt_msg = new unsigned char[MAX_MESSAGE_SIZE];
        memcpy(buffer, username, usernameLen);
        start += usernameLen;
        memcpy(buffer+start, cert_buff, cert_len);
        start+=cert_len;
        memcpy(buffer+start, nonceClient, NONCE_SIZE);
        start+=NONCE_SIZE;
        memcpy(buffer+start, nonceServer, NONCE_SIZE);

        crypto.readPublicKey((const char*)username, user_pubkey);
        encrypted_msg_len = crypto.publicKeyEncryption(buffer,bufferLen,encrypt_msg,user_pubkey);
        serverSocket.sendMessage(sd,encrypt_msg,encrypted_msg_len);
    }catch(const exception& e) {
        delete[] cert_buff;
        delete[] buffer;
        delete[] encrypt_msg;
        throw;
    }
    delete[] cert_buff;
    delete[] buffer;
    delete[] encrypt_msg;
}

string authentication(int sd, unsigned char *messageReceived, unsigned int message_len) {
    unsigned char *nonceServer = NULL;
    unsigned char *nonceClient = NULL;
    unsigned char *username = NULL;
    unsigned char *buffer = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *password = NULL;
    unsigned char *hashedPwd = NULL;
    unsigned char *finalDigest = NULL;
    EVP_PKEY *prvkey = NULL;
    unsigned int bufferLen;
    unsigned int usernameLen;
    unsigned int plainlen;
    unsigned int passwordLen;
    string usernameStr;
    try {
        // Generate nonce
        nonceServer = new unsigned char[NONCE_SIZE];
        crypto.generateNonce(nonceServer);

        // Get peer nonce
        nonceClient = new unsigned char[NONCE_SIZE];
        memcpy(nonceClient, messageReceived+message_len-NONCE_SIZE, NONCE_SIZE);
        // Get peer username
        usernameLen = message_len-NONCE_SIZE-1;
        username = new unsigned char[usernameLen];
        memcpy(username, messageReceived+1, usernameLen);
        cout << "Client username: " << username << endl;

        //Send Certificate
        sendCertificate(sd, username, usernameLen, nonceClient, nonceServer);

        //Receive hashed passwords
        buffer = new unsigned char[MAX_MESSAGE_SIZE];
        bufferLen = serverSocket.receiveMessage(sd, buffer);
        plaintext = new unsigned char[bufferLen];
        crypto.readPrivateKey(prvkey);
        plainlen = crypto.publicKeyDecryption(buffer, bufferLen,plaintext,prvkey);

        password = new unsigned char[MAX_MESSAGE_SIZE];
        passwordLen = readPassword(username, usernameLen, password);

        hashedPwd = new unsigned char[passwordLen + NONCE_SIZE];
        memcpy(hashedPwd, password, passwordLen);
        memcpy(hashedPwd+passwordLen, nonceServer, NONCE_SIZE);

        finalDigest = new unsigned char[DIGEST_LEN];
        crypto.computeHash(hashedPwd, passwordLen + NONCE_SIZE, finalDigest);

        if(memcmp(plaintext, finalDigest, DIGEST_LEN) != 0) {
            throw runtime_error("Wrong Password");
        }
        usernameStr = string((const char *)username);
        cout << "Client " << usernameStr << " authenticated." << endl;
    } catch(const exception& e) {
        delete[] nonceServer;
        delete[] nonceClient;
        delete[] username;
        delete[] buffer;
        delete[] plaintext;
        throw;
    }
    delete[] nonceServer;
    delete[] nonceClient;
    delete[] username;
    delete[] buffer;
    delete[] plaintext;
    return usernameStr;
}

void keyEstablishment(int sd, unsigned int key_pos){
    unsigned char *buffer = NULL;
    unsigned char *secret = NULL;
    unsigned int key_len;
    EVP_PKEY *prv_key_a = NULL;
    EVP_PKEY *pub_key_b = NULL;

    try {
        // Generate public key
        crypto.keyGeneration(prv_key_a);
        
        // Receive peer's public key
        buffer = new unsigned char[MAX_MESSAGE_SIZE];
        key_len = serverSocket.receiveMessage(sd, buffer);
        crypto.deserializePublicKey(buffer, key_len, pub_key_b);

        // Send public key to peer
        key_len = crypto.serializePublicKey(prv_key_a, buffer);
        serverSocket.sendMessage(sd, buffer, key_len);

        // Secret derivation
        secret = new unsigned char[DIGEST_LEN];
        crypto.secretDerivation(prv_key_a, pub_key_b, secret);

        cout << "O' secret: " << endl;
        BIO_dump_fp(stdout, (const char*)secret, DIGEST_LEN);

        crypto.insertKey(secret, key_pos);
    } catch(const exception& e) {
        delete[] buffer;
        delete[] secret;
        throw;
    }
    
    delete[] buffer;
    delete[] secret;
}

void sendOnlineUsers(vector<onlineUser> onlineUsers, onlineUser user) {
    unsigned char *encryptedMessage;
    unsigned int encryptedMessageLen;
    string message = "";
    string username = user.username;
    unsigned int keyPos = user.key_pos;
    int sd = user.sd;
    try {
        for (onlineUser user : onlineUsers) {
            if(username.compare(user.username) != 0) {
                message.append(user.username);
                message.append("\n");
            }
        }
        if(message.length() == 0) {
            message.append("You are the only online user");
        }
        crypto.setSessionKey(keyPos);
        encryptedMessage = new unsigned char[MAX_MESSAGE_SIZE];
        encryptedMessageLen = crypto.encryptMessage((unsigned char *)message.c_str(), message.length(), encryptedMessage);
        serverSocket.sendMessage(sd, encryptedMessage, encryptedMessageLen);
    } catch(const exception& e) {
        delete[] encryptedMessage;
        throw;
    }
}

onlineUser getUser(vector<onlineUser> onlineUsers, string username){
    for (onlineUser user : onlineUsers) {
        if(username.compare(user.username) == 0) {
            return user;
        }
    }
    throw runtime_error("The user is not online");
}

void requestToTalkProtocol(unsigned char *msg, unsigned int msgLen, onlineUser peer_a, vector<onlineUser> onlineUsers) {
    unsigned char *buffer_a;
    unsigned char *nonce_a;
    unsigned char *username_b;
    unsigned char *buffer_b;
    unsigned char *nonce_b;
    unsigned char *nonces;
    unsigned char *pubkey_a_stream;
    unsigned char *pubkey_b_stream;
    unsigned char *encrypt_msg_to_b;
    unsigned char *encrypt_msg_to_a;
    unsigned int buffer_a_len;
    unsigned int pubkey_a_size;
    unsigned int pubkey_b_size;
    unsigned int buffer_b_len;
    unsigned int username_b_len;
    unsigned int encrypted_msg_to_b_len;
    unsigned int encrypted_msg_to_a_len;
    unsigned int start = 0;
    onlineUser peer_b;
    EVP_PKEY *pubkey_a;
    EVP_PKEY *pubkey_b;
    uint64_t nonces_len;
    try {
        // Decrypt Message M1 OPCODE||{USR_B||Na}SA
        if(memcmp(msg, OP_REQUEST_TO_TALK, 1) != 0) {
            throw runtime_error("Request to talk failed.");
        }
        buffer_b = new unsigned char[msgLen];
        crypto.setSessionKey(peer_a.key_pos);
        buffer_b_len = crypto.decryptMessage(msg+1, msgLen-1, buffer_b); //Not consider the OPCODE
        username_b_len = buffer_b_len-NONCE_SIZE;
        username_b = new unsigned char[username_b_len];
        memcpy(username_b,buffer_b,username_b_len);
        nonce_a = new unsigned char[NONCE_SIZE];
        memcpy(nonce_a,buffer_b+username_b_len,NONCE_SIZE);

        peer_b = getUser(onlineUsers,string((const char*)username_b));

        // Encrypt Message M2 OPCODE||{PKa||Na}SB
        buffer_a = new unsigned char[MAX_MESSAGE_SIZE];
        crypto.readPublicKey(peer_a.username,pubkey_a);
        pubkey_a_stream = new unsigned char[MAX_MESSAGE_SIZE];
        pubkey_a_size = crypto.serializePublicKey(pubkey_a,pubkey_a_stream);
        memcpy(buffer_a,pubkey_a_stream,pubkey_a_size);
        start += pubkey_a_size;
        memcpy(buffer_a + start, nonce_a, NONCE_SIZE);
        buffer_a_len = pubkey_a_size + NONCE_SIZE + 1;
        encrypt_msg_to_b = new unsigned char[MAX_MESSAGE_SIZE];
        crypto.setSessionKey(peer_b.key_pos);
        encrypted_msg_to_b_len =  crypto.encryptMessage(buffer_a,buffer_a_len,encrypt_msg_to_b);

        // Append OPCODE as clear text
        memcpy(buffer_a, OP_REQUEST_TO_TALK, 1);
        memcpy(buffer_a+1,encrypt_msg_to_b,encrypted_msg_to_b_len);
        serverSocket.sendMessage(peer_b.sd,buffer_a,encrypted_msg_to_b_len+1);

        // Decrypt Message M3 {OK||{Na||Nb}PKa}SB
        msgLen = serverSocket.receiveMessage(peer_b.sd, msg);
        crypto.setSessionKey(peer_b.key_pos);
        buffer_b_len = crypto.decryptMessage(msg, msgLen, buffer_b);
        if(memcmp(buffer_b, "OK", 2) != 0){
            throw runtime_error("Request to talk failed.");
        }
        nonces_len = msgLen - 2;
        nonces = new unsigned char[nonces_len];
        memcpy(nonces,msg+2,nonces_len);

        // Encrypt Message M4 {nonLen||OK||{Na||Nb}PKa||PKb} --> nonLen = 64 bits
        buffer_a = new unsigned char[MAX_MESSAGE_SIZE];
        memset(buffer_a,0,MAX_MESSAGE_SIZE);
        start = 0;
        memcpy(buffer_a,(const void*)nonces_len,8);
        start += 8;
        memcpy(buffer_a + start, "OK", 2);
        start += 2;
        memcpy(buffer_a + start, nonces, nonces_len);
        start += nonces_len;
        crypto.readPublicKey((string)peer_a.username,pubkey_b);
        pubkey_b_stream = new unsigned char[MAX_MESSAGE_SIZE];
        pubkey_b_size = crypto.serializePublicKey(pubkey_b,pubkey_b_stream);
        memcpy(buffer_a + start,pubkey_b_stream,pubkey_b_size);
        start += pubkey_b_size;
        encrypt_msg_to_a = new unsigned char[MAX_MESSAGE_SIZE];
        crypto.setSessionKey(peer_a.key_pos);
        encrypted_msg_to_a_len =  crypto.encryptMessage(buffer_a,start,encrypt_msg_to_a);
        serverSocket.sendMessage(peer_a.sd,encrypt_msg_to_a,encrypted_msg_to_a_len);

        // Decrypt Message M5
        msgLen = serverSocket.receiveMessage(peer_a.sd, msg);
        crypto.setSessionKey(peer_a.key_pos);
        buffer_b_len = crypto.decryptMessage(msg, msgLen, buffer_b);
        if(memcmp(buffer_b, "OK", 2) != 0){
            throw runtime_error("Request to talk failed.");
        }

        // Encrypt Message M6
        crypto.setSessionKey(peer_b.key_pos);
        encrypted_msg_to_b_len =  crypto.encryptMessage(buffer_b,buffer_b_len,encrypt_msg_to_b);
        serverSocket.sendMessage(peer_b.sd,encrypt_msg_to_b,encrypted_msg_to_b_len);

        // Decrypt Message M7
        msgLen = serverSocket.receiveMessage(peer_b.sd, msg);
        crypto.setSessionKey(peer_b.key_pos);
        buffer_a_len = crypto.decryptMessage(msg, msgLen, buffer_a);
        if(memcmp(buffer_a, "OK", 2) != 0){
            throw runtime_error("Request to talk failed.");
        }

        // Encrypt Message M8
        crypto.setSessionKey(peer_a.key_pos);
        encrypted_msg_to_a_len =  crypto.encryptMessage(buffer_a,buffer_a_len,encrypt_msg_to_a);
        serverSocket.sendMessage(peer_a.sd,encrypt_msg_to_a,encrypted_msg_to_a_len);
    } catch(const std::exception& e) {
        delete[] buffer_b;
        delete[] username_b;
        delete[] nonce_a;
        delete[] buffer_a;
        delete[] pubkey_a_stream;
        delete[] encrypt_msg_to_b;
        delete[] nonces;
        delete[] buffer_a;
        delete[] pubkey_b_stream;
        delete[] encrypt_msg_to_a;
        throw;
    }
    delete[] buffer_b;
    delete[] username_b;
    delete[] nonce_a;
    delete[] buffer_a;
    delete[] pubkey_a_stream;
    delete[] encrypt_msg_to_b;
    delete[] nonces;
    delete[] buffer_a;
    delete[] pubkey_b_stream;
    delete[] encrypt_msg_to_a;
}