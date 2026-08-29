# restrict_process_port.py
#
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
from bcc.libbcc import lib as libbcc
import os

ALLOWED_PORT = 4040
TARGET_COMM = "myprocess"
CGROUP_PATH = "/sys/fs/cgroup/myproc_cg"


bpf_text = f"""
#include <linux/ip.h>
#include <linux/tcp.h>

#define ALLOWED_PORT {ALLOWED_PORT}

// NOTE: We don't check the process name (bpf_get_current_comm) inside
// this program because that helper is not permitted for CGROUP_SKB
// programs on this kernel. It's also unnecessary: this program is only
// ever attached to /sys/fs/cgroup/myproc_cg, and only "myprocess" is
// placed into that cgroup. So cgroup membership itself IS the process
// filter -- any traffic reaching this hook already belongs to our
// target process.

int cgroup_egress_filter(struct __sk_buff *skb) {{
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
    return 0;       // drop everything else for processes in this cgroup
}}
"""

if __name__ == "__main__":
    b = BPF(text=bpf_text)
    fn = b.load_func("cgroup_egress_filter", BPF.CGROUP_SKB)

    # This is exactly what BPF.attach_func() does internally in versions of
    # BCC where it's available -- it just calls libbpf's bpf_prog_attach().
    # We call it directly here since this BCC build doesn't expose the
    # attach_func wrapper method.
    cgroup_fd = os.open(CGROUP_PATH, os.O_RDONLY)

    ret = libbcc.bpf_prog_attach(fn.fd, cgroup_fd, BPF_CGROUP_INET_EGRESS, 0)
    if ret < 0:
        os.close(cgroup_fd)
        raise OSError(
            "bpf_prog_attach failed (return code %d). "
            "Make sure you're running as root and the cgroup path exists." % ret
        )

    print(f"Filter attached to cgroup: {CGROUP_PATH}")
    print(f"Any process placed in this cgroup (e.g. '{TARGET_COMM}') may only")
    print(f"send TCP traffic to port {ALLOWED_PORT}. Processes outside this")
    print("cgroup are unaffected. Press Ctrl+C to detach.")

    try:
        while True:
            pass
    except KeyboardInterrupt:
        pass
    finally:
        # Mirrors BPF.detach_func() -- calls libbpf's bpf_prog_detach2().
        libbcc.bpf_prog_detach2(fn.fd, cgroup_fd, BPF_CGROUP_INET_EGRESS)
        os.close(cgroup_fd)
        print("\nFilter detached.")
