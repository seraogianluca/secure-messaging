// Connections

#define PORT 8080
#define SERVER "127.0.0.1"

// Operation Codes

#define OP_LOGIN 0
#define OP_LOGOUT 1
#define OP_REQUEST_TO_TALK 2
#define OP_MESSAGE 3
#define OP_CERTIFICATE_REQUEST 4

#define MAX_MESSAGE_SIZE 10000
#define MAX_CLIENTS 10

// Authenticated encryption
#define AUTH_ENCR EVP_aes_128_gcm()
#define KEY_SIZE 16
#define IV_SIZE 12
#define TAG_SIZE 16

