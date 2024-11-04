/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

#include "includes/headers.p4"
 
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        inthdr_h inthdr = pkt.lookahead<inthdr_h>();
        transition select(inthdr.header_type) {
            2: parse_notify_packet_head;
            3: parse_notify_packet_head;
            default: parse_ethernet;
        }
    }

    //通知数据包
    state parse_notify_packet_head{
        pkt.extract(hdr.inthdr);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPECODE_IPV4:  parse_ipv4;
            TYPECODE_IPV6:  parse_ipv6;
            TYPECODE_ROCE:  parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPECODE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition accept;
    }
}

struct flow_detection_data {
    bit<32> timestamp; //上一次更新时间
    bit<32> size; //流大小，单位为bytes
};


control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{   
    #define EXPIRE_TIME_INTERVAL 100
    
    Register<bit<32>, PortId_t>(size=255) mirror_packet_register;

    RegisterAction<bit<32>, PortId_t, bit<1>>(mirror_packet_register)mirror_packet_register_update = {
        void apply(inout bit<32> reg, out bit<1> result){
            result = 0;
            if (meta.timestamp_new > EXPIRE_TIME_INTERVAL + reg){
                //发送通知包
                reg = meta.timestamp_new;
                result = 1;
            }
            
        }
    };

    Register<bit<32>, bit<32>>(size=4) notify_packet_register;

    RegisterAction<bit<32>, bit<32>, bit<1>>(notify_packet_register)notify_packet_register_update = {
        void apply(inout bit<32> reg){
            reg=reg+1;
        }
    };

    //mirror 操作, mirror session为 pathId
    action acl_mirror() {
        ig_dprsr_md.mirror_type = 2;
        meta.inthdr.setValid();
        meta.inthdr.header_type = 2;
        meta.inthdr.path_id = meta.path_id;
    }

    action set_path(PortId_t path_id){
        meta.path_id = path_id;
    }

    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        meta.port_id = port;    
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    //路由相关
    //每个lpm对应一个路径group
    //每个路径group对应若干个路径id，ActionProfile实时更新最好的，每个路径id绑定一个port

    ActionProfile(16) group_path;

    table ipv4_lpm_group {
        key = { hdr.ipv4.dst_addr : lpm; }
        actions = {
            set_path; drop;
            @defaultonly NoAction;
        }
        implementation = group_path;
        const default_action = NoAction();
        size = 16;
    }

    table ipv6_lpm_group {
        key = { hdr.ipv6.dst_gid : lpm; }
        actions = {
            set_path; drop;
            @defaultonly NoAction;
        }
        implementation = group_path;
        const default_action = NoAction();
        size = 16;
    }

    table path_port {
        key = {meta.path_id: exact;}
        actions = {
            send; drop;
            @defaultonly NoAction;
        }
        size = 16;
    }

    table ipv4_host {
        key = { hdr.ipv4.dst_addr : exact; }
        actions = {
            send; drop;
            @defaultonly NoAction;
        }
        
        const default_action = NoAction();
        size = 16;
    }

    apply {
        //处理通知包
        if(hdr.inthdr.isValid()){
            notify_packet_register_update.execute((bit<32>)hdr.inthdr.header_type);
            if(hdr.inthdr.header_type == 2){//下游交换机第一次接收到
                hdr.inthdr.header_type = 3; //标记为返回包
                hdr.inthdr.egress_queue_length = (bit<32>)ig_tm_md.ucast_egress_port; //先将原有的port信息暂时存到egress_queue_length字段里面
                ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port; //端口原路返回
            }
            else{//数据返回给了上游交换机
            //else if(hdr.inthdr.header_type == 3){
                ig_dprsr_md.digest_type = 1;
                drop();
            }
        }else{
            //正常路由
            if (hdr.ethernet.ether_type == TYPECODE_IPV4) {
                ipv4_lpm_group.apply();
            } else if(hdr.ethernet.ether_type == TYPECODE_ROCE || hdr.ethernet.ether_type == TYPECODE_IPV6){
                ipv6_lpm_group.apply();
            }
            path_port.apply();
        
            //检测是否发送mirror数据包，发送的同时在控制平面更新本地队列信息
            meta.timestamp_new = (bit<32>)(ig_intr_md.ingress_mac_tstamp >> 16);
            bit<1> mirror_decision = mirror_packet_register_update.execute(meta.path_id);
            if(mirror_decision==1){
                acl_mirror();
            }

            //为普通数据包增加包头
            hdr.inthdr.setValid();
            hdr.inthdr.header_type = 1;
        }
    }
}

struct digest_local_t {
    PortId_t port;
}
struct digest_remote_t{
    PortId_t path_id;
    bit<32> egress_queue_length;
}
    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    //通过digest让控制平面处理端口信息
    //Digest<digest_local_t>() digest_local;
    Digest<digest_remote_t>() digest_remote;


    //mirror相关：每隔一段时间mirror一个包作为信使数据包
    Mirror() mirror;

    apply {
        if (ig_dprsr_md.mirror_type == 2) {
            mirror.emit<inthdr_h>((MirrorId_t)meta.path_id, meta.inthdr);
        }

        if(ig_dprsr_md.digest_type == 1){
            digest_remote.pack({hdr.inthdr.path_id, hdr.inthdr.egress_queue_length});
        }
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/




    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        pkt.extract(hdr.inthdr);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/





control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{   
    

    //记录每一个端口目前的出队长度
    Register<bit<32>, PortId_t>(size=100) egress_queue_length_register;
    RegisterAction<bit<32>, PortId_t, bit<32>>(egress_queue_length_register)egress_queue_length_register_update = {
        void apply(inout bit<32> reg){
            reg = (bit<32>)eg_intr_md.enq_qdepth;
        }
    };
    RegisterAction<bit<32>, PortId_t, bit<32>>(egress_queue_length_register)egress_queue_length_register_get = {
        void apply(inout bit<32> reg, out bit<32>ret){
            ret = reg;
        }
    };

    //mirror寄存器测试
    Register<bit<32>, bit<32>>(size=4) mirror_register;
    RegisterAction<bit<32>, bit<32>, bit<32>>(mirror_register)mirror_register_update = {
        void apply(inout bit<32> reg){
            reg = reg + 1;
        }
    };

    apply {
        mirror_register_update.execute((bit<32>)hdr.inthdr.header_type);
        //判断包类型
        if(hdr.inthdr.header_type == 1){
            //正常包，去掉自定义包头
            egress_queue_length_register_update.execute(eg_intr_md.egress_port);
            hdr.inthdr.setInvalid();
            
        }else if(hdr.inthdr.header_type == 2){
            //刚新建的通知包
        }else{
            //if(hdr.inthdr.header_type == 3){
            //从上游交换机来的通知包，要bounce回去
            //这里是用egress_queue_length字段暂存了原路径的端口信息
            bit<32> tmp = egress_queue_length_register_get.execute((PortId_t)hdr.inthdr.egress_queue_length);
            hdr.inthdr.egress_queue_length = tmp;
        }
        
    }
}

    /*********************  D E P A R S E R  ************************/


control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
