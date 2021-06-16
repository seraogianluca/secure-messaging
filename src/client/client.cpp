#include <cstring>
#include <termios.h>
#include "include/socket.h"
#include "include/crypto.h"
#include "include/utils.h"
#include "include/client.h"



void sendRequestToTalk(ClientContext ctx, string usernameB){
    array<unsigned char, NONCE_SIZE> nonce;
    array<unsigned char, NONCE_SIZE> peerNonce;
    array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    array<unsigned char, MAX_MESSAGE_SIZE> signedPart;
    array<unsigned char, MAX_MESSAGE_SIZE> pubKeyDHBuffer;
    vector<unsigned char> buffer;
    vector<unsigned char> signature;
    unsigned int tempBufferLen = 0;
    unsigned int signedPartLen = 0;
    unsigned int pubKeyDHLen = 0;
    EVP_PKEY *keyDHB = NULL;
    EVP_PKEY *keyDHA = NULL;
    EVP_PKEY *pubKeyB = NULL;
    string usernameB;
    bool accepted = false;

    // Get user to connect with
    cout << "Who do you want to chat with?" << endl;
        do {
            getline(cin, usernameB);
            if(usernameB.length() == 0){
                cout << "Insert at least a character." << endl;
            } else if(ctx.userIsPresent(usernameB)) {
                break;
            } else {
                cout << "Insert a valid username" << endl;
            }       
        } while (usernameB.length() == 0);

    // M1: 2||{2,usr_b, n_a}SA ->
    buffer.push_back(OP_REQUEST_TO_TALK);
    ctx.crypto->generateNonce(nonce.data());
    append(usernameB, buffer);
    append(nonce, NONCE_SIZE, buffer);

    encrypt(ctx.crypto, SERVER_SECRET, buffer);
    buffer.insert(buffer.begin(), 1, OP_REQUEST_TO_TALK); // Insert in clear the OPCODE

    send(ctx.clientSocket, buffer);

    buffer.clear();
    // <- M4: 2||{M3||PK_b} SA
    receive(ctx.clientSocket, buffer);
    tempBufferLen = ctx.crypto->decryptMessage(buffer.data(), buffer.size(), tempBuffer.data());

    if(tempBuffer.at(0) != OP_REQUEST_TO_TALK) {
        errorMessage("Request to talk failed", buffer);
        send(ctx.clientSocket, buffer);
        throw runtime_error("Request to talk failed");
    }

    buffer.insert(buffer.end(), tempBuffer.begin(), tempBuffer.begin() + tempBufferLen);
    buffer.erase(buffer.begin());

    pubKeyDHLen = extract(buffer, pubKeyDHBuffer);
    ctx.crypto->deserializePublicKey(pubKeyDHBuffer.data(), pubKeyDHLen, keyDHB);

    extract(buffer, peerNonce);
    signedPartLen = extract(buffer, signedPart); //extraction of the signed part

    signature.insert(signature.end(), pubKeyDHBuffer.begin(), pubKeyDHBuffer.begin() + pubKeyDHLen);
    signature.insert(signature.end(), nonce.begin(), nonce.end());

    tempBufferLen = extract(buffer, tempBuffer);
    ctx.crypto->deserializePublicKey(pubKeyDHBuffer.data(), pubKeyDHLen, pubKeyB);

    bool signatureVerification = ctx.crypto->verifySignature(signedPart.data(), signedPartLen, signature.data(), signature.size(), pubKeyB);
    if(!signatureVerification) {
        errorMessage("Signed not verified", buffer);
        send(ctx.clientSocket, buffer);
        throw runtime_error("Sign verification failed");
    }

    buffer.clear();
    // M5: 2||{2||g^a mod p||<g^a mod p || n_b>PK_a}SA ->
    ctx.crypto->keyGeneration(keyDHA);
    buffer.push_back(OP_REQUEST_TO_TALK);
    pubKeyDHLen = ctx.crypto->serializePublicKey(keyDHA, pubKeyDHBuffer.data());
    append(pubKeyDHBuffer, pubKeyDHLen, buffer);

    signature.clear();
    signature.insert(signature.end(), pubKeyDHBuffer.begin(), pubKeyDHBuffer.begin() + pubKeyDHLen);
    signature.insert(signature.end(), peerNonce.begin(), peerNonce.end());
    signedPartLen = ctx.crypto->sign(signature.data(), signature.size(), signedPart.data(), ctx.prvKeyClient);
    append(signedPart, signedPartLen, buffer);

    encrypt(ctx.crypto, SERVER_SECRET, buffer);
    buffer.insert(buffer.begin(), 1, OP_REQUEST_TO_TALK); // Insert in clear the OPCODE

    send(ctx.clientSocket, buffer);

    // M7: <- 2||{{2||success}AB}

}