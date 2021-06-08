# Secure messaging

## Introducion

Secure messaging is a chatting application that offers confidentiality, integrity and reliability. It achieves confidentiality and integrity through authenticated encryption, whereas reliability with TCP communications.
Secure messaging works on Unix-like systems; we tested it on x86_64 Linux and intel/apple-silicon Mac.

## Server and client authentication

The messages are exchanged between two clients through the server which acts as intermediary. When the application starts, the server must authenticate using a certificate released by a trusted certification authority. Thanks to this certificate, the client can obtain the public key of the server and can be sure that the server is what we expect it to be. Once the server is authenticated, the client send to it the credentials to perform the login. The username is sent in clear but the password is hashed and encrypted with the server public key. Passwords are mantained in a file on the server: for each user there are the username in clear and the hashed password. To avoid replay attacks the messages are exchanged with nonces.

![alt text](resources/authentication.png "Authentication")

## Client-Server session key establishment

Once client and server are authenticated, they starts to establish a session key. For this reason we use the Ephemeral Diffie-Hellman protocol. First the parameters p and g are generated, then the client compute the public key generating the parameter a, and then send it to the server in encrypted way usign the server public key. The server decrypt the message with its own private key, generates the parameter b to compute the secret and then send the public key to the client in an encrypted way, using the client public key. At this point, the client can decrypt the message and compute the secret. At the end, both have the same secret.

![alt text](resources/ke_client-server.png "Client-Server Key Establishment")

## Login protocol

### Server-Auth

![alt text](resources/authentication.png "Authentication")

1) Client hello. M1 C->S: hello||nc
2) Server hello. M2 S->C: hello||nc||ns
3) Client requests certificate. M3 C->S: cert_req||nc||ns
4) Server sends certificate. M4 S->C: cert||nc
//5) Server: S -> C: hello done

- Client verifica il certificato

### Client-Auth

- Client fa l'hash della password
- Client Cripta con la sua chiave pubblica
- Server Decripta con la chiave privata
- Server controlla se la hash è presente nello store

### Client-Server session key establishment

Perfect forward secrecy + replay attack

### Request to talk

![alt text](resources/request-to-talk.png)

### Chat Session Key Estabilishment

![alt text](resources/ke_clientA-clientB.png)

### Diffie-Hellman key exchange

- Client A invia Client B request to talk
- Client B accetta request to talk
- (?)
- Client A calcola chiave pubblica DH e la invia a Client B
- Client B riceve la chiave pubblica DH di client A
- Client B calcola chiave pubblica DH e la invia a Client A
- Client A riceve la chiave pubblica DH di client B
- Client A e Client B calcolano la session key ed eliminano i paramentri
- LA SESSION KEY CALCOLATA NON PUO' ESSERE USATA PER ENCRYPTION, DEVE ESSERE FATTO L'HASH.

## Miscellanea

The communication between client and server is performed using TCP sockets to guarantee the reliability of the messages.
The server allows opening only a chat at a time for each client with at most 10 online users.
To handle this, the server keeps a structure for the online users and a structure for the active chats.
A user in an active chat can close the communication by typing "!deh", in this case, the server will forward the message to the other side and remove the chat from the active ones.
When a chat is closed, the client application is automatically terminated.
