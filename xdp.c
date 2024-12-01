#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); // Adjust size as needed
    __type(key, __u32);         // Key is the source IP address
    __type(value, __u32);       // Value can be anything (e.g., count or flag)
} allocated_ips SEC(".maps");

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ensure the packet has an Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
    {
        return XDP_PASS;
    }

    // Check if it's an IP packet
    if (eth->h_proto != __constant_htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    // Access the IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    {
        return XDP_PASS;
    }

    // Check if it's a TCP packet
    if (ip->protocol != IPPROTO_TCP)
    {
        return XDP_PASS;
    }

    // Access the TCP header
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
    {
        return XDP_PASS;
    }

    // Only monitor port 3333 (example port)
    if (tcp->dest != __constant_htons(3333)) {
        return XDP_PASS;
    }

    // Lookup the source IP address in the allocated_ips map
    __u32 key = ip->saddr;
    __u32 *value = bpf_map_lookup_elem(&allocated_ips, &key);
    
    if (value) {
        // If found, the packet is allowed
        bpf_trace_print("Authorized TCP packet to port 3333\n");
        return XDP_PASS;
    }

    // If not found, the packet is not allowed
    bpf_trace_print("Unauthorized TCP packet to port 3333\n");
    return XDP_DROP;
}