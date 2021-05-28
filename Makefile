CURRENT_DIR = $(shell pwd)
OS = $(shell uname)
TEST_PATH = test/
CLIENT_PATH = src/client/
CRYPTO_PATH = src/crypto/
SERVER_PATH = src/server/
SOCKET_PATH = src/socket/

ifeq ($(OS), Darwin)
$(info "================= Compiling for mac ======================")
TARGET=server_main.out client_main.out
CC=clang++
CFLAGS= ${CPPFLAGS} ${LDFLAGS} -Wall -lcrypto  
endif

ifeq ($(OS), Linux)
$(info "============== Compiling for linux ======================")
TARGET=server_main.out client_main.out
CC=g++
CFLAGS= -lssl -lcrypto -Wall
endif

all: $(TARGET)
server_main.out: socket.o crypto.o server_main.o
	$(CC) server.o crypto.o socket.o server_main.o -o server_main.out -I$(CURRENT_DIR) $(CFLAGS)
client_main.out: socket.o crypto.o client_main.o
	$(CC) client.o socket.o crypto.o client_main.o -o client_main.out -I$(CURRENT_DIR) $(CFLAGS)
crypto.o:
	$(CC) -c $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR) $(CFLAGS)
socket.o: 
	$(CC) -c $(SOCKET_PATH)socket.cpp -I$(CURRENT_DIR) $(CFLAGS)
server_main.o:
	$(CC) -c $(SERVER_PATH)server_main.cpp $(SERVER_PATH)server.cpp -I$(CURRENT_DIR) $(CFLAGS)
client_main.o:
	$(CC) -c $(CLIENT_PATH)client_main.cpp $(CLIENT_PATH)client.cpp -I$(CURRENT_DIR) $(CFLAGS)
clean:
	$(RM) -rf *.o