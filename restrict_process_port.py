#!/usr/bin/env python3
# Problem 2: Allow traffic only on a specific TCP port (default 4040) for
# a given process name (default "myprocess"). All other outbound TCP
# traffic from that process is dropped. Traffic from other processes is
# left untouched.
#
# Approach:
#   Packets alone (as seen by XDP) do not carry process identity, so this
#   uses a cgroup + CGROUP_SKB egress hook instead. Only processes placed
#   inside the target cgroup are affected.
#
# Setup (run these once, as root, before running this script):
#
#   sudo mkdir -p /sys/fs/cgroup/myproc_cg
#
#   # Launch (or move) your target process into that cgroup, e.g.:
#   exec -a myprocess sleep 3600 &
#   echo $! | sudo tee /sys/fs/cgroup/myproc_cg/cgroup.procs
#
# Then run this script:
#   sudo python3 restrict_process_port.py

from bcc import BPF

ALLOWED_PORT = 4040
TARGET_COMM = "myprocess"
CGROUP_PATH = "/sys/fs/cgroup/myproc_cg"

bpf_text = f"""
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>

#define ALLOWED_PORT {ALLOWED_PORT}
#define TARGET_COMM "{TARGET_COMM}"

int cgroup_egress_filter(struct __sk_buff *skb) {{
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // If this packet is not from our target process, allow everything.
    #pragma unroll
    for (int i = 0; i < 16; i++) {{
        if (comm[i] != TARGET_COMM[i])
            goto allow_all;
        if (comm[i] == 0)
            break;
    }}

    // It IS the target process -> only allow the configured port.
    if (skb->protocol != htons(ETH_P_IP))
        return 1;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end) return 1;
    if (ip->protocol != IPPROTO_TCP) return 1;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) return 1;

    if (ntohs(tcp->dest) == ALLOWED_PORT)
        return 1;   // allow
    return 0;       // drop everything else for this process

allow_all:
    return 1;
}}
"""

if __name__ == "__main__":
    b = BPF(text=bpf_text)
    fn = b.load_func("cgroup_egress_filter", BPF.CGROUP_SKB)
    b.attach_func(fn, CGROUP_PATH, BPF.CGROUP_INET_EGRESS)

    print(f"Filter attached to cgroup: {CGROUP_PATH}")
    print(f"Process '{TARGET_COMM}' may only send TCP traffic to port {ALLOWED_PORT}.")
    print("All other processes are unaffected. Press Ctrl+C to detach.")

    try:
        while True:
            pass
    except KeyboardInterrupt:
        pass
    finally:
        b.detach_func(fn, CGROUP_PATH, BPF.CGROUP_INET_EGRESS)
        print("\nFilter detached.")