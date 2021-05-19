#include "include/exchange.h"

void Exchange::createSocket() {
    if ((master_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0){
        throw runtime_error("Error in the creation");
    }
}

void Exchange::serverBind() {
    
}

void Exchange::buildServerSocket() {
    try {
        createSocket();
    } catch(const runtime_error& ex) {
        throw runtime_error(ex.what());
    }
}