CURRENT_DIR = $(shell pwd)
OS = $(shell uname)
TEST_PATH = test/
CLIENT_PATH = src/client/
CRYPTO_PATH = src/crypto/
SERVER_PATH = src/server/
SOCKET_PATH = src/socket/

ifeq ($(OS), Darwin)
$(info "================= Compiling for mac ======================")
TARGET = server_main.out client_main.out
CC = clang++
LINKFLAG = ${LDFLAGS} -lcrypto 
CFLAGS = ${CPPFLAGS} -Wall -std=c++20
endif

ifeq ($(OS), Linux)
$(info "============== Compiling for linux ======================")
TARGET = server_main.out client_main.out
CC = g++
LINKFLAG = -lssl -lcrypto
CFLAGS = -Wall -std=c++2a
endif

all: $(TARGET)
server_main.out: socket.o crypto.o server_main.o
	$(CC) crypto.o socket.o server_main.o -o server_main.out -I$(CURRENT_DIR) $(CFLAGS) $(LINKFLAG) 
client_main.out: socket.o crypto.o client_main.o
	$(CC) socket.o crypto.o client_main.o -o client_main.out -I$(CURRENT_DIR) $(CFLAGS) $(LINKFLAG) 
crypto.o:
	$(CC) -c $(CRYPTO_PATH)crypto.cpp -I$(CURRENT_DIR) $(CFLAGS) 
socket.o:
	$(CC) -c $(SOCKET_PATH)socket.cpp -I$(CURRENT_DIR) $(CFLAGS)  
server_main.o:
	$(CC) -c $(SERVER_PATH)server_main.cpp -I$(CURRENT_DIR) $(CFLAGS)  
client_main.o:
	$(CC) -c $(CLIENT_PATH)client_main.cpp -I$(CURRENT_DIR) $(CFLAGS) 
clean:
	$(RM) -rf *.o