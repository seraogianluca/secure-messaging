# Secure messaging
Secure messaging is a chatting application that offers confidentiality, integrity and reliability. It achieves confidentiality and integrity through authenticated encryption, whereas reliability with TCP communications. 

Secure messaging works on Unix-like systems; we tested it on x86_64 Linux and intel/apple-silicon Mac. 

## Design Choices

- la firma della CA deve essere installata nel client, per evitare di fare un altro server(ricordarsi di fare la CRL!!!)

## Login protocol

### Server-Auth

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
