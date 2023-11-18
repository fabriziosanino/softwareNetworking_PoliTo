# Lab02 - Network Monitoring with eBPF

# Network monitoring with eBPF

Updated program for the network monitoring with eBPF lab of the software networking course. 
- (Part 1) The goal is to gather information at L3/L4, extracting for each pair source and destination endpoint (i.e. considering both IP address and port) and L4 protocol (i.e. TCP or UDP) the number of packets and the total amount of traffic that is exchanged.

## Building

Install pre-requirements:
```sh
sudo apt update
sudo apt install -y clang libelf-dev zlib1g-dev gcc-multilib
```

Init libbpf and bpftool submodules:
```sh
git submodule update --init --recursive
```

Build and install libbpf:
```sh
cd ./libbpf/src
make
sudo make install
# Make sure the loader knows where to find libbpf
sudo ldconfig /usr/lib64
```

Build and install bpftool:
```sh
cd ./bpftool/src
make
sudo make install
```

Build and run the network monitor:
```sh
make
sudo ./network_monitor <ifname>
```