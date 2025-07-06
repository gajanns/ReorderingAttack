#include "client.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <regex>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cstring>

namespace Connection {

    TCPClient::TCPClient(const std::string& p_src_ip, uint16_t p_src_port, const std::string& p_iface)
        : m_src_ip(p_src_ip), m_src_port(p_src_port), m_iface(p_iface), m_sock_fd(-1) {

        if (!init_socket()) {
            throw std::runtime_error("Failed to initialize socket");
        }

        std::cout << LOG_TAG << " Client initialized at IP: " << m_src_ip
                  << ", port: " << m_src_port << ", interface: " << m_iface << "\n";
    }

    TCPClient::~TCPClient() {
        disconnect();
    }

    bool TCPClient::init_socket() {
        sockaddr_in src_addr{};
        src_addr.sin_family = AF_INET;
        src_addr.sin_port = htons(m_src_port);

        if (inet_pton(AF_INET, m_src_ip.c_str(), &src_addr.sin_addr) != 1) {
            std::cerr << LOG_TAG << " Invalid source IP address: " << m_src_ip << "\n";
            return false;
        }

        m_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (m_sock_fd < 0) {
            std::cerr << LOG_TAG << " Socket creation failed: " << strerror(errno) << "\n";
            return false;
        }

        int opt = 1;
        if (setsockopt(m_sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            std::cerr << LOG_TAG << " setsockopt(SO_REUSEADDR) failed: " << strerror(errno) << "\n";
            close(m_sock_fd);
            m_sock_fd = -1;
            return false;
        }

        if (bind(m_sock_fd, reinterpret_cast<sockaddr*>(&src_addr), sizeof(src_addr)) < 0) {
            std::cerr << LOG_TAG << " Bind failed: " << strerror(errno) << "\n";
            close(m_sock_fd);
            m_sock_fd = -1;
            return false;
        }

        return true;
    }


    void TCPClient::sniff_syn_ack() {
        std::string filter = "tcp[tcpflags] & 0x12 == 0x12 and dst host " + m_src_ip +
                             " and dst port " + std::to_string(m_src_port);
        std::string cmd = "timeout 5s tcpdump -i " + m_iface + " -nn -l -c 1 \"" + filter + "\" 2>/dev/null";

        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            std::cerr << "Failed to start tcpdump...";
            return;
        }

        char buffer[512];
        std::string output;
        while (fgets(buffer, sizeof(buffer), pipe)) {
            output += buffer;
        }

        int status = pclose(pipe);
        if (status != 0) {
            std::cerr << "tcpdump exited abnormally or timed out....";
        }

        std::smatch match;
        std::regex pattern(R"(seq (\d+), ack (\d+))");
        if (std::regex_search(output, match, pattern) && match.size() == 3) {
            m_server_state.set_seq(std::stoul(match[1]));
            m_server_state.set_ack(std::stoul(match[2]));
        } else {
            std::cerr << "Failed to parse tcpdump output:..." << output;
        }

        {
            std::lock_guard<std::mutex> lock(m_sniff_mutex);
            m_sniff_done = true;
        }
        m_sniff_cv.notify_one();
    }

    bool TCPClient::exc_connect(const std::string& p_dst_ip, uint16_t p_dst_port) {
        if (m_sock_fd < 0) {
            std::cerr << LOG_TAG << " Socket not initialized.\n";
            return false;
        }

        if (m_server_state.type == State::Type::CONNECTED) {
            std::cerr << LOG_TAG << " Already connected. Disconnect first.\n";
            return false;
        }

        m_dst_ip = p_dst_ip;
        m_dst_port = p_dst_port;

        sockaddr_in dst_addr{};
        dst_addr.sin_family = AF_INET;
        dst_addr.sin_port = htons(m_dst_port);

        if (inet_pton(AF_INET, m_dst_ip.c_str(), &dst_addr.sin_addr) != 1) {
            std::cerr << LOG_TAG << " Invalid destination IP address: " << m_dst_ip << "\n";
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(m_sniff_mutex);
            m_sniff_done = false;
        }

        m_sniff_thread = std::jthread(&TCPClient::sniff_syn_ack, this);

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        if (connect(m_sock_fd, reinterpret_cast<sockaddr*>(&dst_addr), sizeof(dst_addr)) < 0) {
            std::cerr << LOG_TAG << " Connection Failed: " << strerror(errno) << "\n";
            m_sniff_thread.request_stop();
            disconnect();
            return false;
        }

        std::cout << LOG_TAG << " Connected to " << m_dst_ip << ":" << m_dst_port << "...";

        {
            std::unique_lock<std::mutex> lock(m_sniff_mutex);
            if (!m_sniff_cv.wait_for(lock, std::chrono::seconds(5), [this] { return m_sniff_done; })) {
                std::cerr << "Sniffing Failed.\n";
                m_sniff_thread.request_stop();
                disconnect();
                return false;
            }
        }

        std::cout << "Sniffing Succeeded.\n";
        m_server_state.type = State::Type::CONNECTED;

        std::cout << LOG_TAG << " Initial State: " << m_server_state << "\n";
        return true;
    }

    void TCPClient::disconnect() {
        if (m_sock_fd >= 0) {
            close(m_sock_fd);
            m_sock_fd = -1;
            std::cout << LOG_TAG << " Disconnected.\n";
        } else {
            std::cout << LOG_TAG << " Already disconnected.\n";
        }
        m_sniff_thread.request_stop();

        m_server_state.set_seq(0);
        m_server_state.set_ack(0);
        m_server_state.type = State::Type::DISCONNECTED;
        m_sniff_done = false;

        // Re-initialize socket so the client is reusable
        if (!init_socket()) {
            std::cerr << LOG_TAG << " Failed to reinitialize socket.\n";
        }
    }

    std::ostream& operator<<(std::ostream& os, const TCPClient& conn) {
        os << LOG_TAG << " Client State: " << conn.m_server_state
           << ", Source IP: " << conn.m_src_ip
           << ", Source Port: " << conn.m_src_port
           << ", Destination IP: " << conn.m_dst_ip
           << ", Destination Port: " << conn.m_dst_port;
        return os;
    }

} // namespace Connection
