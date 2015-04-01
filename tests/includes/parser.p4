metadata routing_metadata_t routing_metadata;

parser start {
    set_metadata(routing_metadata.drop, 0);
    return parse_ethernet;
}

#define ETHERTYPE_VLAN 0x8100, 0x9100, 0x9200, 0x9300
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86dd
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_RARP 0x8035

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_VLAN : parse_vlan;
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_IPV6 : parse_ipv6;
    }
}

#define VLAN_DEPTH 4
header vlan_tag_t vlan_tag_[VLAN_DEPTH];

parser parse_vlan {
    extract(vlan_tag_[next]);
    return select(latest.etherType) {
        ETHERTYPE_VLAN : parse_vlan;
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_IPV6 : parse_ipv6;
    }
}

#define IP_PROTOCOLS_ICMP 1
#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17
#define IP_PROTOCOLS_ICMPV6 58

header ipv4_t ipv4;

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.fragOffset, latest.protocol) {
        IP_PROTOCOLS_ICMP : parse_icmp;
        IP_PROTOCOLS_TCP : parse_tcp;
        IP_PROTOCOLS_UDP : parse_udp;
    }
}

header ipv6_t ipv6;

parser parse_ipv6 {
    extract(ipv6);
    return select(latest.nextHdr) {
        IP_PROTOCOLS_ICMPV6 : parse_icmpv6;
        IP_PROTOCOLS_TCP : parse_tcp;
        IP_PROTOCOLS_UDP : parse_udp;
    }
}

header icmp_t icmp;

parser parse_icmp {
    extract(icmp);
    return ingress;
}

header icmpv6_t icmpv6;

parser parse_icmpv6 {
    extract(icmpv6);
    return ingress;
}

header tcp_t tcp;

parser parse_tcp {
    extract(tcp);
    return ingress;
}


header udp_t udp;

parser parse_udp {
    extract(udp);
    return ingress;
}

