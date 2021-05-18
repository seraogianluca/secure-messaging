all: remove client server

#remove: 
#	rm client
#	rm server

client: client.cpp
	g++ -Wall -o client client.cpp  -lcrypto

server: server.cpp
	g++ -Wall -o server server.cpp  -lcrypto

TARGET=client server 
CC=clang++ g++
CFLAGS= -Wall -lcrypto -g
normal: $(TARGET)
client: client.cpp
    $(CC) $(CFLAGS) client.c -o client
server: server.cpp
    $(CC) $(CFLAGS) server.c -o server
clean:
    $(RM) $(TARGET)

CPPFLAGS="-I/opt/homebrew/opt/openssl@1.1/include"
LDFLAGS="-L/opt/homebrew/opt/openssl@1.1/lib"

CPPFLAGS="-I/usr/local/opt/openssl@1.1/include"
LDFLAGS="-L/usr/local/opt/openssl@1.1/lib"
