#include <string>
#include <vector>
#include "symbols.h"

using namespace std;

struct user {
    string username;
    int port;
};

class Server {
    private:
        vector<user> onlineUsers;
        int sendMessage(string message);
    public:
        Server();
        ~Server();

        int forwardMessage(string dest, string message);
        int authenticate(string dest);
        int sendOnlineUsers(string dest);
};
