/*######################################################################################################
# Experiment: General
# Description: Establish a TCP connection to a server and extract initial window
# #####################################################################################################*/

#pragma once

#include <string>
#include <cstdint>
#include <mutex>
#include <ostream>
#include <thread>
#include <cstdarg>
#include <condition_variable>
#include "default.hpp"

namespace Connection {
    inline constexpr std::string_view LOG_TAG = "[Connection]";

    struct State {
        private:
            uint32_t m_seq;
            uint32_t m_ack;
            mutable std::mutex m_state_mutex;

        public:
            uint32_t seq() const {
                std::lock_guard<std::mutex> lock(m_state_mutex);
                return m_seq;
            }
            
            uint32_t ack() const {
                std::lock_guard<std::mutex> lock(m_state_mutex);
                return m_ack;
            }
            void set_seq(uint32_t s) {
                std::lock_guard<std::mutex> lock(m_state_mutex);
                m_seq = s;
            }
            
            void set_ack(uint32_t a) {
                std::lock_guard<std::mutex> lock(m_state_mutex);
                m_ack = a;
            }

            enum class Type {
                CONNECTED,
                DISCONNECTED
            } type;

            State() : m_seq(0), m_ack(0), type(Type::DISCONNECTED) {}
            State(const State&) = delete;
            State& operator=(const State&) = delete;


            friend std::ostream& operator<<(std::ostream& os, const State& state) {
                os << (state.type == State::Type::CONNECTED ? "CONNECTED" : "DISCONNECTED")
                << ", SEQ: " << state.seq() << ", ACK: " << state.ack();
                return os;
            }
    };

    class TCPClient {
        private:
            bool init_socket();
            void sniff_syn_ack();
            std::jthread m_sniff_thread;
            mutable std::mutex m_sniff_mutex;
            mutable std::condition_variable m_sniff_cv;
            bool m_sniff_done = false;

            std::string m_src_ip, m_dst_ip;
            uint16_t m_src_port, m_dst_port;
            std::string m_iface;
            int m_sock_fd;
            State m_server_state;

        public:
            TCPClient(const std::string& p_src_ip, const uint16_t p_src_port, const std::string& p_iface);
            TCPClient()
                : TCPClient(Defaults::client_ip.data(), Defaults::client_port, Defaults::iface.data()) {}
            ~TCPClient();

            bool extended_connect(const std::string& p_dst_ip, const uint16_t p_dst_port);
            bool extended_connect() {
                return extended_connect(Defaults::server_ip.data(), Defaults::dst_port);
            }
            void disconnect();
            friend std::ostream& operator<<(std::ostream& os, const TCPClient& conn);

            std::pair<uint32_t, uint32_t> server_state() const {
                return std::make_pair(m_server_state.seq(), m_server_state.ack());
            }
    };

} // namespace Connection
