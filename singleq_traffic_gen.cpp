/*######################################################################################################
# Experiment: Single Queue Traffic Generator
# Description: Generate traffic directed at a single rx queue for in- and out-of-connection scenario
######################################################################################################*/

#include "packetbuilder.hpp"
#include "client.hpp"
#include "default.hpp"

#include <netinet/in.h>
#include <unistd.h>
#include <iostream>
#include <chrono>
#include <arpa/inet.h>
#include <cstring>

// ########################################################################################
// # Region: Configuration
// ########################################################################################

const size_t num_iterations = 1000;
const size_t seq_length = 16;
const std::string payload = "ABC";

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
    // # Region: Initialize Client (Optional)
    // ####################################################################################

    Connection::TCPClient client;
    if (!client.extended_connect()) {
        std::cerr << "Failed to connect to server." << std::endl;
        return 1;
    }

    auto [base_seq, base_ack] = client.server_state();

    // ####################################################################################
    // # Region: Packet Configuration
    // ####################################################################################

    auto probe1_cfg = PacketBuilder::Defaults::probe_config(1);
    auto probe2_cfg = PacketBuilder::Defaults::probe_config(2);
    auto non_spoof_cfg = PacketBuilder::Defaults::probe_config();
    auto spoof_cfg = PacketBuilder::Defaults::spoof_config();
    spoof_cfg.seq = non_spoof_cfg.seq = base_seq;
    spoof_cfg.ack = non_spoof_cfg.ack = base_ack;
    spoof_cfg.payload = non_spoof_cfg.payload = payload;
    spoof_cfg.psh = non_spoof_cfg.psh = !payload.empty();

    const uint32_t delta_seq = (!payload.empty() || spoof_cfg.psh || spoof_cfg.syn || spoof_cfg.rst) ?
                                std::max(static_cast<uint32_t>(payload.size()), 1u) : 0;

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
        bool in_connection = std::rand() % 2 == 0;
        auto& current_cfg = in_connection ? spoof_cfg : non_spoof_cfg;

        PacketBuilder::PacketBatch batch = {
            .probe1 = build_packet(probe1_cfg),
            .spoofed = build_packet_batch(current_cfg, seq_length),
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
            std::cout << "Batch " << (i + 1) << ": Sent " << sent << " packets, "
                      << "type=" << (in_connection ? "IN-CONNECTION" : "OUT-OF-CONNECTION") << ", "
                      << "seq=" << current_cfg.seq << ", ack=" << current_cfg.ack << ", ∆t="
                      << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()
                      << " µs\n";
        }

        if(in_connection) {
            spoof_cfg.seq += delta_seq * seq_length;
        }

        std::this_thread::sleep_for(std::chrono::microseconds(10000));
    }

    close(sock);
    return 0;
}
