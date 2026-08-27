#!/usr/bin/env python3
# Problem 1: Drop TCP packets on a configurable port using eBPF (XDP).
# Usage:
#   sudo python3 drop_port.py <interface> [port]
# Example:
#   sudo python3 drop_port.py ens33 4040
#
# Once running, you can type a new port number at the prompt to change
# which port is being blocked, live, without restarting the program.

from bcc import BPF
import sys
import ctypes as ct

bpf_text = """
#include <bcc/proto.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

// Map to hold the port number that should be blocked.
// Index 0 always holds the current blocked port.
BPF_ARRAY(config_map, u16, 1);

int xdp_drop_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    int key = 0;
    u16 *blocked_port = config_map.lookup(&key);
    if (!blocked_port)
        return XDP_PASS;

    if (ntohs(tcp->dest) == *blocked_port) {
        return XDP_DROP;
    }
    return XDP_PASS;
}
"""

if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4040

    b = BPF(text=bpf_text)
    fn = b.load_func("xdp_drop_port", BPF.XDP)
    b.attach_xdp(iface, fn, 0)

    config_map = b["config_map"]
    config_map[ct.c_int(0)] = ct.c_uint16(port)
    print(f"Dropping TCP traffic on port {port}, interface {iface}. Ctrl+C to stop.")

    try:
        while True:
            new_port = input("Enter new port to block (or Enter to keep current): ")
            if new_port.strip():
                config_map[ct.c_int(0)] = ct.c_uint16(int(new_port))
                print(f"Now blocking port {new_port}")
    except KeyboardInterrupt:
        pass
    finally:
        b.remove_xdp(iface, 0)
        print("\nXDP program detached. All ports unblocked.")