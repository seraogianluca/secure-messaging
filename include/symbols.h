// Connections
#define PORT 8080
#define SERVER "127.0.0.1"

// Operation Codes
#define OP_LOGIN '0'
#define OP_LOGOUT '1'
#define OP_REQUEST_TO_TALK '2'
#define OP_MESSAGE '3'
#define OP_ONLINE_USERS '4'
#define OP_ERROR '5'

#define MAX_MESSAGE_SIZE 10000
#define MAX_CLIENTS 10

#define SERVER_SECRET 0
#define CLIENT_SECRET 1

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
#define CA_CERT_PATH "ca_cert"

//Public key criptography
#define CIPHER EVP_aes_128_cbc()

#define NO_USER_ONLINE "_no_user_online"


