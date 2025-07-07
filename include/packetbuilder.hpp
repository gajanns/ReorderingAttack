#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <sys/socket.h>

namespace packet_builder {

    struct Config {
        std::string src_ip;
        std::string dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint32_t seq = 0;
        uint32_t ack = 0;

        // Flags
        bool syn = false;
        bool ack_flag = false;
        bool rst = false;
        bool psh = false;

        uint16_t window = 65535;

        // Optional payload
        std::string payload = "";
    };

    struct PacketBatch {
        std::vector<char> probe1;
        std::vector<std::vector<char>> spoofed;
        std::vector<char> probe2;

        std::vector<mmsghdr> to_mmsg(std::vector<iovec>& iovecs) const;

    private:
        static mmsghdr make_msg(iovec& iov);
    };

    std::vector<char> build_packet(const Config& config);
    std::vector<std::vector<char>> build_packet_batch(const Config& base_config, size_t packet_count);
}
