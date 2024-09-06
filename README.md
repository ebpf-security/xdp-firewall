# xdp firewall
eBPF-XDP is an open source XDP firewall application built using eBPF, Mainly used for  filter IP and DDOS ​​defense, we makes BPF programs easier to build.
[![Build Status](https://drone.grafana.net/api/badges/grafana/beyla/status.svg?ref=refs/heads/main)](https://ebpf-security.github.io/navihtml/ebpf-xdp.html)

## Requirements
XDP is a part of the upstream Linux kernel, and enables users to inject packet processing programs into the kernel, that will be executed for each arriving packet, before the kernel does any other processing on the data, It runs on/requires Linux Kernel >= 4.18 such as the following platforms:
* Ubuntu 20.10+
* Fedora 31+
* RHEL 8.2+
* Debian 11+
* Rocky Linux 8.5+
* ...

## Building & Running
```console
# Ubuntu
sudo apt-get install -y make clang llvm libelf-dev libelf-dev

# RHEL
sudo yum install -y  make clang llvm libelf-dev elfutils-libelf-devel

$ make && make install 

$ ./build/xdpfw 
  Loaded XDP program in SKB/generic mode.
  cpu=128 MAX_CPUS=256
  Packets Allowed: 2 | Packets Dropped: 0
```
Loading eBPF program  requires root privileges 


## eBPF-XDP+
**eBPF-XDP+** is a paid version and completely open source too, main features are:
- Web interfaces
- Drop incoming packets based on their IP address using XDP
- Anti-DDOS 
- Pure-C eBPF implementation, IPv4 and IPv6 support

**Free Trial**

```console
$ wget https://ebpf-security.github.io/ebpf-xdp
$ chmod +x ./ebpf-xdp 
$ ./ebpf-xdp 
  1. Kill all of  processes...........................
  2. Init  ok.........................................
  3. System is running................................
```

After loading is complete, Open a browser to http://<host>:9998/ to access the Web UI.
Full Trial version available at [https://ebpf-security.github.io/navihtml/ebpf-xdp.html](https://ebpf-security.github.io/navihtml/ebpf-xdp.html)

How to stop?

```console
$ ./ebpf-xdp stop
```

<a href="https://github.com/ebpf-security/ebpf-security.github.io/blob/main/img/1.png"><img height="500" width="820" src="https://github.com/ebpf-security/ebpf-security.github.io/blob/main/img/1.png"></img></a>
&nbsp;


## Contact Us
* Mail to `openhfw@outlook.com`
Before moving on, please consider giving us a GitHub star ⭐️. Thank you!

## License
This project is licensed under the terms of the
[MIT license](/LICENSE).

