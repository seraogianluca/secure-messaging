#include <iostream>
#include <string>
#include "symbols.h"

using namespace std;

class Client {
    private:
        string username;

        int sendMessage(string message);
        string readMessage();
    public:
        Client(); //Constructor
        ~Client(); //Distructor

        int login(string pwd);
        int logout();
        int requestToTalk(string peerUsername);
        int textMessage(string peerUsername, string message);
};