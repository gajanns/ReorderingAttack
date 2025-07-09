/*######################################################################################################
# Experiment: Multi Queue Traffic Generator (RSS)
# Description: Generate traffic directed at a two rx queues for concurrency verification
######################################################################################################*/

#include "packetbuilder.hpp"
#include "default.hpp"

#include <netinet/in.h>
#include <unistd.h>
#include <iostream>
#include <chrono>
#include <arpa/inet.h>
#include <cstring>
#include <thread>

// ########################################################################################
// # Region: Configuration
// ########################################################################################

const size_t num_iterations = 1000;

// ########################################################################################
// # Region: Initialize Sender Socket
// ########################################################################################

int setup_raw_socket(const std::string_view p_iface) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, p_iface.data(), p_iface.size() + 1) < 0) {
        perror("setsockopt(SO_BINDTODEVICE)");
        close(sock);
        return -1;
    }

    int opt = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        close(sock);
        return -1;
    }

    return sock;
}

// ########################################################################################
// # Region: Main
// ########################################################################################

int main() {

    // ####################################################################################
    // # Region: Packet Configuration
    // ####################################################################################

    auto probe1_cfg = PacketBuilder::Defaults::probe_config(1);
    probe1_cfg.src_port = MultiQAttacker::Defaults::queue0_port;
    auto probe2_cfg = PacketBuilder::Defaults::probe_config(2);
    probe2_cfg.src_port = MultiQAttacker::Defaults::queue1_port;

    // ####################################################################################
    // # Region: Setup Socket
    // ####################################################################################

    int sock = setup_raw_socket(Connection::Defaults::iface);
    if (sock < 0) return 1;

    sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(Connection::Defaults::dst_port);

    if (inet_pton(AF_INET, Connection::Defaults::server_ip.data(), &dest_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return 1;
    }

    // ####################################################################################
    // # Region: Traffic Generation
    // ####################################################################################
    
    for (size_t i = 0; i < num_iterations; ++i) {

        PacketBuilder::PacketBatch batch = {
            .probe1 = std::vector<char>(),
            .spoofed = PacketBuilder::build_packet_batch(probe1_cfg,2),
            .probe2 = build_packet(probe2_cfg)
        };

        std::vector<iovec> iovecs;
        std::vector<mmsghdr> msgs = batch.to_mmsg(iovecs);

        for (auto& msg : msgs) {
            msg.msg_hdr.msg_name = &dest_addr;
            msg.msg_hdr.msg_namelen = sizeof(dest_addr);
        }

        auto start = std::chrono::steady_clock::now();
        int sent = sendmmsg(sock, msgs.data(), msgs.size(), 0);
        auto end = std::chrono::steady_clock::now();

        if (sent < 0) {
            perror("sendmmsg");
        } else {
            std::cout   << "Batch " << (i + 1) << ": Sent " << sent << " packets, "
                        << "Time taken: " << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()
                        << " microseconds" << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::microseconds(10000));
    }

    close(sock);
    return 0;
}
