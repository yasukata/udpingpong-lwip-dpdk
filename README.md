# UDP ping-pong on lwIP on DPDK

## Target platform

The author tested this on Ubuntu 20.04.

## Requirements

meson and ninja are used for DPDK compilation. ( Please see https://doc.dpdk.org/guides/linux_gsg/build_dpdk.html for details. )

Please install them if you do not have yet.

- meson
- ninja

## Build

The following commands will compile the lwIP and DPDK applied application.

```
git clone https://github.com/yasukata/udpingpong-lwip-dpdk.git
```

```
cd udpingpong-lwip-dpdk
```

```
make
```

### What Makefile does

Makefile produces a file named app that is bound with lwIP and DPDK.

Our Makefile downloads the source code of lwIP and DPDK, and compile them. The source code and the build objects of lwIP and DPDK are located in the directory where our Makefile is located.

The following is the detailed procedure that our Makefile conducts.

1. download required the source code of lwIP and DPDK.

- lwIP: ([LOCATION_OF_MAKEFILE]/lwip/lwip-$(LWIP_VER).zip) http://download.savannah.nongnu.org/releases/lwip/lwip-$(LWIP_VER).zip
- lwIP contrib: ([LOCATION_OF_MAKEFILE]/lwip/contrib-$(CONTRIB_VER).zip) http://download.savannah.nongnu.org/releases/lwip/contrib-$(CONTRIB_VER).zip
- DPDK: ([LOCATION_OF_MAKEFILE]/dpdk/dpdk-$(DPDK_VER).tar.xz) https://fast.dpdk.org/rel/dpdk-$(DPDK_VER).tar.xz

2. extract the source code

- lwIP: ([LOCATION_OF_MAKEFILE]/lwip/lwip-$(LWIP_VER))
- lwIP contrib: ([LOCATION_OF_MAKEFILE]/lwip/contrib-$(CONTRIB_VER))
- DPDK: ([LOCATION_OF_MAKEFILE]/dpdk/dpdk-$(DPDK_VER))

3. compile and install DPDK

DPDK is installed in a directory [LOCATION_OF_MAKEFILE]/dpdk/install .

Therefore, you do not need the root permission for installation, and this does not overwrite the existing DPDK library.

## How to use

We assume the command is executed in the top directory of this repository. So, please cd to tinyhttpd-lwip-dpdk.

```
cd udpingpong-lwip-dpdk
```

### Launch a server

```
sudo LD_LIBRARY_PATH=./dpdk/install/lib/x86_64-linux-gnu ./app -l 0-1 --proc-type=primary --file-prefix=pmd1 --allow=0000:04:00.1 -- -a 10.0.0.2 -g 10.0.0.1 -m 255.255.255.0 -p 10000 
```

- -a: ip address
- -g: gateway
- -m: netmask
- -p: server listen port

### Launch a client

```
sudo LD_LIBRARY_PATH=./dpdk/install/lib/x86_64-linux-gnu ./app -l 0-1 --proc-type=primary --file-prefix=pmd1 --allow=0000:04:00.1 -- -a 10.0.0.3 -g 10.0.0.1 -m 255.255.255.0 -s 10.0.0.2 -p 10000 -q 8 -l 32
```

- -a: ip address
- -g: gateway
- -m: netmask
- -s: server address
- -p: server port
- -l: additional payload size
- -q: queue depth (number of max in-flight packets, namely, number of ping-pong balls)

### Behavior

- Both the server and client simply reply received data
- The client initially transmits several packets (number of queue depth/ping-pong balls) to initiate ping-pong
- The payload of each UDP packet contains an integer number, that is an id of an ping-pong ball
- The client prints the number of received packets every second
