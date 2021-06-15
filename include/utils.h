#include <array>
#include <vector>
#include <algorithm>
#include "socket.h"
#include "symbols.h"

template<size_t contentSize>
void append(std::array<unsigned char, contentSize> content, unsigned int contentLen, std::vector<unsigned char> &buffer) {
    unsigned char sizeArray[2];
    uint16_t size = 0;

    if (contentLen > UINT16_MAX)
        throw std::runtime_error("Content too big.");

    size = (uint16_t)contentLen;

    sizeArray[0] = size & 0xFF; //low part
    sizeArray[1] = size >> 8;   //higher part

    buffer.insert(buffer.end(), sizeArray, sizeArray + 2);
    buffer.insert(buffer.end(), content.begin(), content.begin() + contentLen);
}

template<size_t bufferSize>
int extract(std::vector<unsigned char> &content, std::array<unsigned char, bufferSize> &buffer) {
    unsigned char sizeArray[2];
    uint16_t size = 0;

    std::copy_n(content.begin(), 2, sizeArray);
    size = sizeArray[0] | uint16_t(sizeArray[1]) << 8;
    content.erase(content.begin(), content.begin() + 2);

    if(size > bufferSize)
        throw std::runtime_error("Buffer too short.");

    std::copy_n(content.begin(), size, buffer.begin());
    content.erase(content.begin(), content.begin() + size);

    return size;
}

template<size_t msgSize>
void receive(Socket *socket, int sd, vector<unsigned char> &buffer) {
    std::array<unsigned char, MAX_MESSAGE_SIZE> msg;
    unsigned int size;

    size = socket->receiveMessage(sd, msg.data());
    buffer.insert(buffer.end(), msg.begin(), msg.begin() + size);
}

void send(Socket *socket, int sd, vector<unsigned char> &buffer) {
    size = socket->sendMessage(sd, buffer.data(), buffer.size());
    buffer.clear();
}