# txRay

**t**raffic **xRay** (txRay) is a tool based on eBPF and tracepoint , used for 
counting traffic transferred between network endpoints.

There are other types of eBPf programs that achieve same purpose (e.g. socket filter, kprobe,TC bpf as I know), so the repo
just a toy in my process of learning eBPF and to demonstrate how to combine tracepoint and eBPF.
## Prerequisites
1. BTF (BPF Type Format) : make sure the host contains directory `/sys/kernel/btf`.
2. Kernel version: Maybe kernel 5.x is required. As said before, old kernels do not contain directory `/sys/kernel/btf`.

## How to use 
```shell
# clone repo
git clone git@github.com:stricklandye/txRay.git

# build
git build .

sudo ./txRay --interface=enp6s0 --port=443
time="2023-11-25T19:59:20+08:00" level=info msg="txRay starts, press Ctrl + C to stop"
time="2023-11-25T19:59:39+08:00" level=info msg="stop txRay"
time="2023-11-25T19:59:39+08:00" level=info msg="txRay exits by SIGNAL:terminated"
pid          comm                 saddr                    daddr                    protocol     sent_bytes   recv_bytes   interface
2898         clash-linux          192.168.0.108:46866      114.230.222.141:443      TCP          80           40           enp6s0
2898         clash-linux          192.168.0.108:40436      183.131.147.48:443       TCP          80           40           enp6s0
2898         clash-linux          192.168.0.108:47214      183.131.147.28:443       TCP          80           40           enp6s0
2898         clash-linux          192.168.0.108:47910      115.223.46.215:443       TCP          2376         4539         enp6s0
2898         clash-linux          192.168.0.108:58308      118.89.204.198:443       TCP          7730         6718         enp6s0
```