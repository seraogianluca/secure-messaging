# secure-messagging

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
