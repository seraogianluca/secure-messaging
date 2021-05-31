// Connections
#define PORT 8080
#define SERVER "127.0.0.1"

// Operation Codes
#define OP_LOGIN ((unsigned char*)"0")
#define OP_LOGOUT ((unsigned char*)"1")
#define OP_REQUEST_TO_TALK ((unsigned char*)"2")
#define OP_MESSAGE ((unsigned char*)"3")
#define OP_CERTIFICATE_REQUEST ((unsigned char*)"4")

#define MAX_MESSAGE_SIZE 10000
#define MAX_CLIENTS 10

// Nonces
#define NONCE_SIZE 16

// Authenticated encryption
#define AUTH_ENCR EVP_aes_128_gcm()
#define IV_SIZE 12
#define TAG_SIZE 16

// Hash
#define HASH EVP_sha256()
#define DIGEST_LEN EVP_MD_size(HASH)

//CERTIFICATE PATH
#define CA_CERT_PATH "./cert/ca_cert.pem"

