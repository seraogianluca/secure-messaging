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
	$(CC) $(CPPFLAGS) $(LDFLAGS) $(CFLAGS) -o crypto $(TEST_PATH)crypto_tests.cpp $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR)
#client: $(CLIENT_PATH)client_main.cpp $(CLIENT_PATH)client.cpp
#	$(CC) $(CPPFLAGS) $(LDFLAGS) $(CFLAGS) -o client $(CLIENT_PATH)client_main.cpp $(CLIENT_PATH)client.cpp $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR)
#server: $(SERVER_PATH)server_main.cpp $(SERVER_PATH)server.cpp
#	$(CC) $(CPPFLAGS) $(LDFLAGS) $(CFLAGS) -o server $(SERVER_PATH)server_main.cpp $(SERVER_PATH)server.cpp $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR)
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
	$(CC) $(CPPFLAGS) $(LDFLAGS) $(CFLAGS) -o client $(CLIENT_PATH)client_main.cpp $(CLIENT_PATH)client.cpp $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR)
server: $(SERVER_PATH)server_main.cpp $(SERVER_PATH)server.cpp
	$(CC) $(CPPFLAGS) $(LDFLAGS) $(CFLAGS) -o server $(SERVER_PATH)server_main.cpp $(SERVER_PATH)server.cpp $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR)
clean:
	$(RM) $(TARGET)       
endif

ifeq ($(ENV), 3)
$(info "==============Compiled by Lorenzo======================")
TARGET=client server
CC=g++
CFLAGS= -Wall -lcrypto

all: $(TARGET)
client: $(CLIENT_PATH)client_main.cpp $(CLIENT_PATH)client.cpp
	$(CC) $(CFLAGS) -o client $(CLIENT_PATH)client_main.cpp $(CLIENT_PATH)client.cpp $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR)
server: $(SERVER_PATH)server_main.cpp $(SERVER_PATH)server.cpp
	$(CC) $(CFLAGS) -o server $(SERVER_PATH)server_main.cpp $(SERVER_PATH)server.cpp $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR)
clean:
	$(RM) $(TARGET)
endif