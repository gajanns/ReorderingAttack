#pragma once
#include "packetbuilder.hpp"

namespace connection_defaults {
    inline constexpr std::string_view server_ip = "10.0.3.196";
    inline constexpr uint16_t dst_port = 8080;
    inline constexpr std::string_view client_ip = "10.0.3.196";
    inline constexpr uint16_t client_port = 12340;
    inline constexpr std::string_view iface = "lo";
}

namespace attacker_defaults {
    inline constexpr std::string_view attacker_ip = "10.0.3.196";
    inline constexpr uint16_t attacker_port = 12345;
    inline constexpr uint16_t probe1_port = 12346; 
    inline constexpr uint16_t probe2_port = 12347;
}

namespace packet_builder_defaults {
    using packet_builder::Config;

    inline constexpr uint32_t base_seq = 1000;
    inline constexpr uint32_t base_ack = 5000;

    inline Config probe_config(int id = 0) {
        return Config{
            .src_ip = std::string(attacker_defaults::attacker_ip),
            .dst_ip = std::string(connection_defaults::server_ip),
            .src_port = [&id]{
                switch (id) {
                    case 1: return attacker_defaults::probe1_port;
                    case 2: return attacker_defaults::probe2_port;
                    default: return attacker_defaults::attacker_port;
                }
            }(),
            .dst_port = connection_defaults::dst_port,
            .seq = base_seq,
            .ack = base_ack,
            .syn = false,
            .ack_flag = true,
            .window = 65535
        };
    }

    inline Config spoof_config() {
        Config cfg = probe_config();
        cfg.src_ip = std::string(connection_defaults::client_ip);
        cfg.src_port = connection_defaults::client_port;
        cfg.syn = false;
        cfg.ack_flag = true;
        cfg.psh = false;
        cfg.payload = "";
        return cfg;
    }
}
