# txRay

**t**raffic **xRay** (txRay) is a tool based on eBPF and tracepoint , used for 
counting traffic transferred between network endpoints.

There are other types of eBPf programs that achieve same purpose (e.g. socket filter, kprobe,TC bpf as I know), so the repo
just a toy in my process of learning eBPF and to demonstrate how to combine tracepoint and eBPF.
## Prerequisites
1. BTF (BPF Type Format) : make sure the host contains directory `/sys/kernel/btf`.
2. Kernel version: Maybe kernel 5.x is required. As said before, old kernels do not contain directory `/sys/kernel/btf`.
