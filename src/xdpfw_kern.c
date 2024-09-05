#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <stdatomic.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <bpf_helpers.h>

#include "xdpfw.h"



#ifdef DEBUG
#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

struct bpf_map_def SEC("maps") hi_ports_map = 
{
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = MAX_FILTER_PORTS
};

struct bpf_map_def SEC("maps") hi_stats_map =
{
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct stats),
    .max_entries = 1
};

struct bpf_map_def SEC("maps") hi_ip_stats_map =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct ip_stats),
    .max_entries = MAX_TRACK_IPS
};

struct bpf_map_def SEC("maps") hi_ip_blacklist_map =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = MAX_TRACK_IPS
};

struct bpf_map_def SEC("maps") hi_ip6_blacklist_map =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u128),
    .value_size = sizeof(__u32),
    .max_entries = MAX_TRACK_IPS
};



/*struct bpf_map_def SEC("maps") ip6_stats_map =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u128),
    .value_size = sizeof(struct ip_stats),
    .max_entries = MAX_TRACK_IPS
};

struct bpf_map_def SEC("maps") ip6_blacklist_map =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u128),
    .value_size = sizeof(__u64),
    .max_entries = MAX_TRACK_IPS
};*/

SEC("hi_xdp_prog")
int hi_xdp_prog_main(struct xdp_md *ctx)
{
    // Initialize data.
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Scan ethernet header.
    struct ethhdr *eth = data;

    // Check if the ethernet header is valid.
    if (eth + 1 > (struct ethhdr *)data_end)
    {
        return XDP_DROP;
    }

    // Check Ethernet protocol.
    if (unlikely(eth->h_proto != htons(ETH_P_IP) && eth->h_proto != htons(ETH_P_IPV6)))
    {
        return XDP_PASS;
    }

    __u8 action = 0;
    __u64 blocktime = 1;

    // Initialize IP headers.
    struct iphdr *iph = NULL;
    struct ipv6hdr *iph6 = NULL;
    __u128 srcip6 = 0;


    // Set IPv4 and IPv6 common variables.
    if (eth->h_proto == htons(ETH_P_IPV6))
    {
        iph6 = (data + sizeof(struct ethhdr));

        if (unlikely(iph6 + 1 > (struct ipv6hdr *)data_end))
        {
            return XDP_DROP;
        }

        memcpy(&srcip6, &iph6->saddr.in6_u.u6_addr32, sizeof(srcip6));
    }
    else
    {
        iph = (data + sizeof(struct ethhdr));

        if (unlikely(iph + 1 > (struct iphdr *)data_end))
        {
            return XDP_DROP;
        }
    }
    
    // Check IP header protocols.
    if (iph6 || iph == NULL)
    {
        return XDP_PASS;
    }

    // Get stats map.
    __u32 key = 0;
    struct stats *stats = bpf_map_lookup_elem(&hi_stats_map, &key);

    __u64 now = bpf_ktime_get_ns();
    __u32 *allow_port = NULL;
    __u32  port = 0;



    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    struct icmphdr *icmph = NULL;
    struct icmp6hdr *icmp6h = NULL;

    if (stats)
    {
        
        stats->allowed++;
    }
    
    // Check protocol.
   if (iph)
    {   
        switch (iph->protocol)
        {
            case IPPROTO_TCP:
                // Scan TCP header.
                tcph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));

                // Check TCP header.
                if (tcph + 1 > (struct tcphdr *)data_end)
                {
                    return XDP_DROP;
                }

                port = ntohs(tcph->dest);  
                
                break;

            case IPPROTO_UDP:
                // Scan UDP header.
                udph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));

                // Check TCP header.
                if (udph + 1 > (struct udphdr *)data_end)
                {
                    return XDP_DROP;
                }

                port = ntohs(udph->dest);         

                break;

            case IPPROTO_ICMP:
                // Scan ICMP header.
                icmph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));

                // Check ICMP header.
                if (icmph + 1 > (struct icmphdr *)data_end)
                {
                    return XDP_DROP;
                }

                port = 0;

                break;
        }
    }


    allow_port =  bpf_map_lookup_elem(&hi_ports_map, &port);
    if (allow_port != NULL && *allow_port == 1 && port != 22 && port != 9998) {                       
        #ifdef DEBUG
            bpf_printk("Checking for blocked port... iph->saddr=%x PORT=%u\n",iph->saddr, port);
        #endif   
   
        if (stats)       {
              stats->dropped++;
        }
                      
        return XDP_DROP; 
    }
   
   // Check blacklist map.
    __u32 *blocked = NULL;   

    if (iph6) {  
        blocked = bpf_map_lookup_elem(&hi_ip6_blacklist_map, &srcip6);   
       // if (blocked != NULL && *blocked > 0)   
            // bpf_printk("hi_ip6_blacklist_map for blocked packet...%x",(__u32)srcip6);
    }

    if (iph)   {
         blocked = bpf_map_lookup_elem(&hi_ip_blacklist_map, &iph->saddr);
    }
   
    if (blocked != NULL && *blocked > 0)    {
        #ifdef DEBUG
         // bpf_printk("Checking for blocked packet... iph->saddr=%x Block  %u\n",iph->saddr, *blocked);
        #endif   
   
        if (stats)       {
             stats->dropped++;
        }
       
        return XDP_DROP;       
    }
   
    

            
    return XDP_PASS;

}

char _license[] SEC("license") = "GPL";
