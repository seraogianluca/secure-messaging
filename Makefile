setEnvironment:
ifdef GIAN_ENV
    ENV=1
endif
ifdef ANT_ENV
    ENV=2
endif
ifdef LO_ENV
    ENV=3
endif

CURRENT_DIR = $(shell pwd)
TEST_PATH = test/
CLIENT_PATH = src/client/
CRYPTO_PATH = src/crypto/
SERVER_PATH = src/server/

ifeq ($(ENV), 1)
$(info "=================Compiled by Gianluca======================")
TARGET= crypto
CC=clang++
CFLAGS= -Wall -lcrypto
CPPFLAGS="-I/opt/homebrew/opt/openssl@1.1/include"
LDFLAGS="-L/opt/homebrew/opt/openssl@1.1/lib"
all: $(TARGET)
crypto: $(TEST_PATH)crypto_tests.cpp $(CRYPTO_PATH)crypto.cpp
	$(CC) $(CPPFLAGS) $(LDFLAGS) -o crypto $(TEST_PATH)crypto_tests.cpp $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR) $(CFLAGS)
#client: $(CLIENT_PATH)client_main.cpp $(CLIENT_PATH)client.cpp
#	$(CC) $(CPPFLAGS) $(LDFLAGS) -o client $(CLIENT_PATH)client_main.cpp $(CLIENT_PATH)client.cpp $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR) $(CFLAGS)
#server: $(SERVER_PATH)server_main.cpp $(SERVER_PATH)server.cpp
#	$(CC) $(CPPFLAGS) $(LDFLAGS) -o server $(SERVER_PATH)server_main.cpp $(SERVER_PATH)server.cpp $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR) $(CFLAGS)
clean:
	$(RM) $(TARGET)       
endif

ifeq ($(ENV), 2)
$(info "==================Compiled by Antonio======================")
TARGET=client server
CC=clang++
CFLAGS= -Wall -lcrypto
CPPFLAGS="-I/usr/local/opt/openssl@1.1/include"
LDFLAGS="-L/usr/local/opt/openssl@1.1/lib"
all: $(TARGET)
client: $(CLIENT_PATH)client_main.cpp $(CLIENT_PATH)client.cpp
	$(CC) $(CPPFLAGS) $(LDFLAGS) -o client $(CLIENT_PATH)client_main.cpp $(CLIENT_PATH)client.cpp $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR) $(CFLAGS)
server: $(SERVER_PATH)server_main.cpp $(SERVER_PATH)server.cpp
	$(CC) $(CPPFLAGS) $(LDFLAGS) -o server $(SERVER_PATH)server_main.cpp $(SERVER_PATH)server.cpp $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR) $(CFLAGS)
clean:
	$(RM) $(TARGET)       
endif

ifeq ($(ENV), 3)
$(info "==============Compiled by Lorenzo======================")
#TARGET=client server
TARGET=crypto_client crypto_server
CC=g++
CFLAGS= -lssl -lcrypto -Wall

all: $(TARGET)
crypto_client: $(TEST_PATH)crypto_client.cpp $(CRYPTO_PATH)crypto.cpp
	$(CC) -o crypto_client $(TEST_PATH)crypto_client.cpp $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR) $(CFLAGS) 
crypto_server: $(TEST_PATH)crypto_server.cpp $(CRYPTO_PATH)crypto.cpp
	$(CC) -o crypto_server $(TEST_PATH)crypto_server.cpp $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR) $(CFLAGS)
client: $(CLIENT_PATH)client_main.cpp $(CLIENT_PATH)client.cpp
	$(CC) -o client $(CLIENT_PATH)client_main.cpp $(CLIENT_PATH)client.cpp $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR) $(CFLAGS)
server: $(SERVER_PATH)server_main.cpp $(SERVER_PATH)server.cpp
	$(CC) -o server $(SERVER_PATH)server_main.cpp $(SERVER_PATH)server.cpp $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR) $(CFLAGS)
clean:
	$(RM) $(TARGET)
endif