#include <iostream>
#include "client.hpp"

int main(int, char**){
    std::cout << "Hello, from ReorderingAttack!\n";
    Connection::TCPClient client("10.0.0.137", 12345, "lo");
}
