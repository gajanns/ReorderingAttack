FROM ubuntu:24.04

RUN apt-get update && apt-get -y install --no-install-recommends \
    gcc-13 g++-13 gdb cmake make git  \
    net-tools ethtool tcpdump tshark

# Install Python and pip
RUN apt-get install -y python3 python3-matplotlib python3-scapy python3-numpy python3-pandas

