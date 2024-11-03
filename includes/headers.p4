
//l3类型
const bit<16> TYPECODE_TPID = 0x8100;
const bit<16> TYPECODE_IPV4 = 0x0800;
const bit<16> TYPECODE_IPV6 = 0x86DD;
const bit<16> TYPECODE_ARP = 0x0806;
const bit<16> TYPECODE_ROCE = 0x8915;

//l4类型
const bit<8> TYPECODE_UDP = 17;
const bit<8> TYPECODE_TCP = 6;

//RoCE相关
const bit<16> ROCE_PORT = 4791;

typedef bit<4> ecmp_hash_t;


header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

//InfiniBand
header ib_transport_h {
    bit<8> op_code;
    bit<1> solicited_event;
    bit<1> mig_reg;
    bit<2> pad_count;
    bit<4> header_version;
    bit<16> partition_key;
    bit<8> reserved;
    bit<24> dst_qp;
    bit<1> ack;
    bit<7> reserved_2;
    bit<24> pkt_seq_num;
}

header ib_route_h {
    bit<4> ip_version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_length;
    bit<8> next_header;
    bit<8> hop_limit;
    bit<128> src_gid; //ipv6地址
    bit<128> dst_gid;
}

//header_type: default-正常包 1-第一次mirror的包 2-mirror之后返回的包 3-正常包(egress里使用)
header inthdr_h {
    bit<7> header_type;
    PortId_t path_id;
    bit<32> egress_queue_length;
}


//mirror用
header ing_port_mirror_h {
    bit<7> pad0; PortId_t ingress_port;
    bit<6> pad1; MirrorId_t mirror_session;
}


struct my_ingress_headers_t {
    inthdr_h     inthdr;
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    udp_h        udp;
    ib_route_h   ib_route;
    ib_transport_h   ib_transport;
}

struct my_ingress_metadata_t {
    ecmp_hash_t ecmp_hash_value; //当前五元组的hash结果
    bit<32> timestamp_new;
    PortId_t path_id; //转发后选择的路径号
    PortId_t port_id; //转发后选择的路径号
    bit<16> pkt_length;
    inthdr_h inthdr;
    ing_port_mirror_h ing_port_mirror;
}

struct my_egress_headers_t {
    inthdr_h     inthdr;
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    udp_h        udp;
    ib_route_h   ib_route;
    ib_transport_h   ib_transport;
}



struct my_egress_metadata_t {
    inthdr_h inthdr;
    ing_port_mirror_h ig_mirror;
}

