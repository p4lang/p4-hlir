#include "includes/headers.p4"
#include "includes/parser.p4"

action hop(ttl, egress_spec) {
    add_to_field(ttl, -1);
    modify_field(standard_metadata.egress_spec, egress_spec, 0xFFFFFFFF);
}

action hop_ipv4(egress_spec) {
    hop(ipv4.ttl, egress_spec);
}

/* This should not be necessary if drop is allowed in table action specs */
action drop_pkt() {
    drop();
}

table ipv4_routing {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
      drop_pkt;
      hop_ipv4;
    }
}

action act() {
    count(cnt1, 10);
}

table table_2 {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        act;
    }
}

counter cnt1 {
    type : packets;
    static : table_2;
    instance_count : 32;
}

register reg1 {
    width : 20;
    static : ipv4_routing;
    instance_count : 100;
    attributes : saturating, signed;
}

register reg2 {
    layout : ipv4_t;
    direct : ipv4_routing;
}
    

control ingress {
    apply(ipv4_routing);
    apply(table_2);
}

control egress {

}