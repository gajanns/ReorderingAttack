/*######################################################################################################
# Experiment: General (Single Queue for now)
# Description: Encapsulate default configurations for connection and attacker settings
# #####################################################################################################*/

#pragma once

#include "packetbuilder.hpp"

namespace Connection::Defaults {
    inline constexpr std::string_view server_ip = "10.100.2.2";
    inline constexpr uint16_t dst_port = 8080;
    inline constexpr std::string_view client_ip = "10.100.2.100";
    inline constexpr uint16_t client_port = 65000;
    inline constexpr std::string_view iface = "enp1s0np1";
}

namespace SingleQAttacker::Defaults {
    inline constexpr std::string_view attacker_ip = "10.100.2.1";
    inline constexpr uint16_t attacker_port = 65021;
    inline constexpr uint16_t probe1_port = 65011; 
    inline constexpr uint16_t probe2_port = 65031;
}

namespace MultiQAttacker::Defaults {
    inline constexpr std::string_view attacker_ip = "10.100.2.1";
    inline constexpr uint16_t probe1_port = 65011; 
    inline constexpr uint16_t probe2_port = 65030;
}

namespace PacketBuilder::Defaults {
    using PacketBuilder::Config;

    inline constexpr uint32_t base_seq = 1000;
    inline constexpr uint32_t base_ack = 5000;

    inline Config probe_config(int id = 0) {
        return Config{
            .src_ip = std::string(SingleQAttacker::Defaults::attacker_ip),
            .dst_ip = std::string(Connection::Defaults::server_ip),
            .src_port = [&id]{
                switch (id) {
                    case 1: return SingleQAttacker::Defaults::probe1_port;
                    case 2: return SingleQAttacker::Defaults::probe2_port;
                    default: return SingleQAttacker::Defaults::attacker_port;
                }
            }(),
            .dst_port = Connection::Defaults::dst_port,
            .seq = base_seq,
            .ack = base_ack,
            .syn = false,
            .ack_flag = true,
            .window = 65535
        };
    }

    inline Config spoof_config() {
        Config cfg = probe_config();
        cfg.src_ip = std::string(Connection::Defaults::client_ip);
        cfg.src_port = Connection::Defaults::client_port;
        cfg.syn = false;
        cfg.ack_flag = true;
        cfg.psh = false;
        cfg.payload = "";
        return cfg;
    }
}
