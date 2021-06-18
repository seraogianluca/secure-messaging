#include <array>
#include <vector>
#include <algorithm>
#include <openssl/bio.h>
#include "symbols.h"
#include "crypto.h"

void printBuffer(string message, std::vector<unsigned char> buffer) {
    cout << message << endl;
    BIO_dump_fp(stdout, (const char*)buffer.data(), buffer.size());
}

template<size_t contentSize>
void printBuffer(string message, std::array<unsigned char, contentSize> content, unsigned int contentLen) {
    cout << message << endl;
    BIO_dump_fp(stdout, (const char*)content.data(), contentLen);
}

void printBuffer(std::vector<unsigned char> buffer) {
    BIO_dump_fp(stdout, (const char*)buffer.data(), buffer.size());
}

template<size_t contentSize>
void append(std::array<unsigned char, contentSize> content, unsigned int contentLen, std::vector<unsigned char> &buffer) {
    unsigned char sizeArray[2];
    uint16_t size = 0;

    if (contentLen > UINT16_MAX)
        throw std::runtime_error("Content too big.");
    
    if (contentLen > UINT_MAX - buffer.size() - sizeof(uint16_t))
        throw runtime_error("Content too big.");
    
    if (buffer.size() + contentLen + sizeof(uint16_t) > MAX_MESSAGE_SIZE)
        throw runtime_error("Content too big.");

    size = (uint16_t)contentLen;

    sizeArray[0] = size & 0xFF; //low part
    sizeArray[1] = size >> 8;   //higher part

    buffer.insert(buffer.end(), sizeArray, sizeArray + 2);
    buffer.insert(buffer.end(), content.begin(), content.begin() + contentLen);
}

void append(std::string content, std::vector<unsigned char> &buffer) {
    unsigned char sizeArray[2];
    uint16_t size = 0;

    if (content.length() > UINT16_MAX)
        throw std::runtime_error("Content too big.");
    
    if (content.length() > UINT_MAX - buffer.size() - sizeof(uint16_t))
        throw runtime_error("Content too big.");
    
    if (buffer.size() + content.length() + sizeof(uint16_t) > MAX_MESSAGE_SIZE)
        throw runtime_error("Content too big.");

    size = (uint16_t)content.length();

    sizeArray[0] = size & 0xFF; //low part
    sizeArray[1] = size >> 8;   //higher part

    buffer.insert(buffer.end(), sizeArray, sizeArray + 2);
    buffer.insert(buffer.end(), content.begin(), content.end());
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

std::string extract(std::vector<unsigned char> &content) {
    std::string buffer;
    unsigned char sizeArray[2];
    uint16_t size = 0;

    std::copy_n(content.begin(), 2, sizeArray);
    size = sizeArray[0] | uint16_t(sizeArray[1]) << 8;
    content.erase(content.begin(), content.begin() + 2);

    buffer = std::string(content.begin(), content.begin() + size);
    content.erase(content.begin(), content.begin() + size);

    return buffer;
}

void errorMessage(std::string errorMessage, std::vector<unsigned char> &buffer) {
    buffer.clear();
    buffer.insert(buffer.end(), OP_ERROR);
    append(errorMessage, buffer);
}

void encrypt(Crypto *crypto, unsigned int key, std::vector<unsigned char> &buffer) {
    std::array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    unsigned int tempBufferLen;

    try {
        crypto->setSessionKey(key);
        tempBufferLen = crypto->encryptMessage(buffer.data(), buffer.size(), tempBuffer.data());

        buffer.clear();
        buffer.insert(buffer.end(), tempBuffer.begin(), tempBuffer.begin() + tempBufferLen);
    } catch(const std::exception& e) {
        throw;
    }
}

void decrypt(Crypto *crypto, unsigned int key, std::vector<unsigned char> &buffer) {
    std::array<unsigned char, MAX_MESSAGE_SIZE> tempBuffer;
    unsigned int tempBufferLen;

    try {
        crypto->setSessionKey(key);
        tempBufferLen = crypto->decryptMessage(buffer.data(), buffer.size(), tempBuffer.data());

        buffer.clear();
        buffer.insert(buffer.end(), tempBuffer.begin(), tempBuffer.begin() + tempBufferLen);
    } catch(const std::exception& e) {
        throw;
    }
}