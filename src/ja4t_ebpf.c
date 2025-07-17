#include <vmlinux.h> // This should provide all kernel types and definitions
#include <bpf/bpf_helpers.h> // For BPF helper functions
#include <bpf/bpf_endian.h> // For bpf_ntohs, etc.
#include <bpf/bpf_core_read.h>

struct ja4t_data {
    __u32 saddr;          // Source IP address
    __u16 dport;          // Destination port
    __u16 window_size;    // TCP Window Size
    __u16 mss;            // Maximum Segment Size (from option)
    __u8  window_scale;   // Window Scale (from option)
    __u8  options_len;    // Actual number of options found
    __u8  options[16];    // Array to store option kinds (JA4T uses up to 6, but generous size)
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct ja4t_data));
} events SEC(".maps");

#ifndef TC_ACT_OK
#define TC_ACT_OK           0
#endif
#define TCP_OPTION_MSS      2
#define TCP_OPTION_WSCALE   3
#define TCP_OPTION_SACK_PERM 4
#define TCP_OPTION_TIMESTAMP 8

SEC("tc_ingress")
int ja4t_collector(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Check minimum size for Ethernet + IP + TCP header (20 bytes for each)
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return TC_ACT_OK;

    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);

    // Basic sanity checks
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return TC_ACT_OK; // TCP header incomplete

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK; // Not a TCP packet

    // Check for SYN packet (SYN set, ACK not set)
    if (!(tcp->syn) || (tcp->ack))
        return TC_ACT_OK;

    // Initialize our data structure to send to user-space
    struct ja4t_data ja4t_evt = {};
    ja4t_evt.saddr = ip->saddr;
    ja4t_evt.dport = bpf_ntohs(tcp->dest);
    ja4t_evt.window_size = bpf_ntohs(tcp->window);
    ja4t_evt.mss = 0; // Default if not found
    ja4t_evt.window_scale = 0; // Default if not found
    ja4t_evt.options_len = 0;

    // TCP options parsing
    __u8 tcp_hdr_len = tcp->doff * 4;
    void *tcp_options_start = (void *)tcp + sizeof(struct tcphdr);
    void *tcp_options_end = (void *)tcp + tcp_hdr_len;

    // Iterate through TCP options
    void *opt_ptr = tcp_options_start;
    while (opt_ptr < tcp_options_end) {
        if (opt_ptr + 1 > data_end) break; // Check if kind byte is accessible

        __u8 kind = *(volatile __u8 *)opt_ptr;
        __u8 len = 0;

        if (kind == 0) { // End of Option List
            break;
        } else if (kind == 1) { // NOP
            len = 1;
        } else {
            if (opt_ptr + 2 > data_end) break; // Check if length byte is accessible
            len = *(volatile __u8 *)(opt_ptr + 1);
            if (len < 2) break; // Malformed option
        }

        if (opt_ptr + len > data_end) break; // Check if entire option fits in packet

        // Store option kind in order
        if (ja4t_evt.options_len < sizeof(ja4t_evt.options)) {
            ja4t_evt.options[ja4t_evt.options_len++] = kind;
        }

        // Extract specific option values
        if (kind == TCP_OPTION_MSS) { // Kind 2
            if (len == 4) { // MSS option is 4 bytes long (kind, len, 2-byte value)
                ja4t_evt.mss = bpf_ntohs(*(volatile __u16 *)(opt_ptr + 2));
            }
        } else if (kind == TCP_OPTION_WSCALE) { // Kind 3
            if (len == 3) { // Window scale is 3 bytes long (kind, len, 1-byte value)
                ja4t_evt.window_scale = *(volatile __u8 *)(opt_ptr + 2);
            }
        }
        // Add more parsing for other options if required by a specific JA4T variant

        opt_ptr += len;
    }

    // Send the collected data to user-space
    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &ja4t_evt, sizeof(ja4t_evt));

    return TC_ACT_OK; // Allow the packet to proceed
}

char _license[] SEC("license") = "GPLv3";

