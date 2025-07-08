#include <iostream>
#include "client.hpp"

int main(int, char**){
    std::cout << "Hello, from ReorderingAttack!\n";
    Connection::TCPClient client;
    client.extended_connect();
}
