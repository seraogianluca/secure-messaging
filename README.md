# Secure messaging

## Introducion

Secure messaging is a chatting application that offers confidentiality, integrity and reliability. It achieves confidentiality and integrity through authenticated encryption, whereas reliability with TCP communications.
Secure messaging works on Unix-like systems; we tested it on x86_64 Linux and intel/apple-silicon Mac.

## Server and client authentication

The messages are exchanged between two clients through the server which acts as intermediary. When the application starts, the server must authenticate using a certificate released by a trusted certification authority. Thanks to this certificate, the client can obtain the public key of the server and can be sure that the server is what we expect it to be. Once the server is authenticated, the client send to it the credentials to perform the login. The username is sent in clear but the password is hashed and encrypted with the server public key. Passwords are mantained in a file on the server: for each user there are the username in clear and the hashed password. To avoid replay attacks the messages are exchanged with nonces.

![alt text](resources/authentication.png "Authentication")

## Client-Server session key establishment

Once client and server are authenticated, they starts to establish a session key. For this reason we use the Ephemeral Diffie-Hellman protocol, to guarantee the Perfect Forwar Secrecy. First the parameters p and g are generated, then the client compute the public key generating the parameter a, and then send it to the server in encrypted way usign the server public key. The server decrypt the message with its own private key, generates the parameter b to compute the secret and then send the public key to the client in an encrypted way, using the client public key. At this point, the client can decrypt the message and compute the secret. At the end, both have the same secret.

![alt text](resources/ke_client-server.png "Client-Server Key Establishment")

## Request to talk

An user, before to start a chat with another user, must send to him a request to talk which can be accepted or not by the receiver. All the message exchanged between each client with the server are encrypted with the session key previously estabilished, as we have said in the previous paragraph. The request to talk protocol works in the following way:

1) CLIENT A -> SERVER: Client A send to the server a message which has the username of the user he want to chat with and a nonce to guarantee freshness against replay attack. This part of the message is encrypted and at the beginning there is the OPCODE relative to the request to talk (2) that is in clear.

2) SERVER -> CLIENT B: now the server knows that it must send a request to talk to the client B, whose username is knows from the message previously received and decrypted. The first 64 bits of the message are composed with the username length of the sender. Then there is the username sender, the public key of the sender and the nounce. This is all encrypted, then the message is sent to client B with the OPCODE = 2 at the beginning of the message in clear.

3) CLIENT B -> SERVER: at this point, client B can accept of refuse the request to talk sent by A.  It sends to the server an OK messagge to which is appended the nonce of A and the nonce just generate from B, both encrypted with the public key of A. If client B wants to refuse the request to talk the process is the same but he sends only a message with NO to the server which is forwarded to the client A.

4) SERVER -> CLIENT A: to the message received, after the OK, the server adds the public key of B. Then the message is the same of before.

5) CLIENT A -> SERVER: client A decrypt the message and in particular its nonce to verify it is the same one that sent earlier. If the verification was successful, it sends to the server an OK message to which is appended the nonce of A and B encrypted with the public key of B just received.

6) SERVER -> CLIENT B: now the server performs just the forwarding of the message. The only operation which it performs is the change of the session key with the right one depending on the client it communicates with.

7) CLIENT B -> SERVER: client B receives the message and decrypt it, in particular its own nonce to verify it is the same one that sent earlier. If it is, he sends to the server an OK message.

8) SERVER -> CLIENT A: the server forward the OK message to client A. At this point the request to talk was successful.

At the end of this process, the server added the two clients to the active chat struct, to remember which users are chatting with each other.

![alt text](resources/request-to-talk.png)

## Client A-Client B session key establishment

![alt text](resources/ke_clientA-clientB.png)

## Miscellanea

- The communication between client and server is performed using TCP sockets to guarantee the reliability of the messages.
- The server allows opening only a chat at a time for each client with at most 10 online users. To handle this, the server keeps a structure for the online users and a structure for the active chats.
- A user in an active chat can close the communication by typing "!deh", in this case, the server will forward the message to the other side and remove the chat from the active ones.
- When a chat is closed, the client application is automatically terminated.
