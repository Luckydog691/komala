from ipaddress import ip_address
# port manage
port = bfrt.port
# Initializing all tables
port_table = port.port
port_fp_idx_info_table = port.port_fp_idx_info
port_hdl_info_table = port.port_hdl_info
port_stat_table = port.port_stat
port_str_info_table = port.port_str_info
p4 = bfrt.komala

ipv4_lpm_group = p4.pipe.Ingress.ipv4_lpm_group
ipv6_lpm_group = p4.pipe.Ingress.ipv6_lpm_group
group_path = p4.pipe.Ingress.group_path
path_port = p4.pipe.Ingress.path_port

port_table.clear()
ipv4_lpm_group.clear()
ipv6_lpm_group.clear()
group_path.clear()
path_port.clear()

# add_ports 
# 使能交换机网口，并设置速率，虽然是100G的网卡和网口，但是因为有的线上限40G，只能设 40G；这里用 bfrt 设置的，也能通过注释里的命令设置，后面有写
port_table.add(dev_port=56, speed="BF_SPEED_100G", fec="BF_FEC_TYP_NONE", port_enable=True) # port-add 9/0 100g none && port-enb -/- # 该端口没有受限电缆，speed 设置 100G 也能使用
port_table.add(dev_port=48, speed="BF_SPEED_100G", fec="BF_FEC_TYP_NONE", port_enable=True) # port-add 10/0 100g none && port-enb -/-
port_table.add(dev_port=40, speed="BF_SPEED_100G", fec="BF_FEC_TYP_NONE", port_enable=True)

path_port.add_with_send(path_id=1, port=56) # 165 9-> 【201 10->】 165
bfrt.mirror.cfg.entry_with_normal(sid=1,ucast_egress_port=56,
        direction="BOTH",session_enable=True,ucast_egress_port_valid=1,max_pkt_len=100,packet_color="GREEN").push()

path_port.add_with_send(path_id=2, port=48) # 165 10-> 【201 9->】 165
bfrt.mirror.cfg.entry_with_normal(sid=2,ucast_egress_port=48,
        direction="BOTH",session_enable=True,ucast_egress_port_valid=1,max_pkt_len=100,packet_color="GREEN").push()

path_port.add_with_send(path_id=3, port=56) # 165 9-> 200 11-> 【201 9->】 165
bfrt.mirror.cfg.entry_with_normal(sid=3,ucast_egress_port=56,
        direction="BOTH",session_enable=True,ucast_egress_port_valid=1,max_pkt_len=100,packet_color="GREEN").push()

path_port.add_with_send(path_id=4, port=40) # 165 9-> 【201 11->】 200 9-> 165
bfrt.mirror.cfg.entry_with_normal(sid=4,ucast_egress_port=40,
        direction="BOTH",session_enable=True,ucast_egress_port_valid=1,max_pkt_len=100,packet_color="GREEN").push()

# 201/9
group_path.add_with_set_path(action_member_id=1, path_id=1)
#group_path.add_with_set_path(action_member_id=1, path_id=3)
ipv4_lpm_group.add(dst_addr=ip_address('192.168.30.122'), dst_addr_p_length=32, action_member_id=1) 
ipv6_lpm_group.add(dst_gid=ip_address('fe80::bace:f6ff:fe9a:6e'), dst_gid_p_length=128, action_member_id=1)


# 201/10
group_path.add_with_set_path(action_member_id=2, path_id=2)
ipv4_lpm_group.add(dst_addr=ip_address('192.168.30.123'), dst_addr_p_length=32, action_member_id=2)
ipv6_lpm_group.add(dst_gid=ip_address('fe80::bace:f6ff:fe9a:6f'), dst_gid_p_length=128, action_member_id=2)


# 200/9
group_path.add_with_set_path(action_member_id=4, path_id=4)
ipv4_lpm_group.add(dst_addr=ip_address('192.168.20.124'), dst_addr_p_length=32, action_member_id=4) # 200/9
ipv6_lpm_group.add(dst_gid=ip_address('fe80::ac0:ebff:fe24:6e52'), dst_gid_p_length=128, action_member_id=4)



digest_count=0
local_port_engress_data=[]
for i in range(200):
    local_port_engress_data.append(0)

egress_queue_length_register = p4.pipe.Egress.egress_queue_length_register
def local_digest_callback(dev_id, pipe_id, direction, parser_id, session, msg):
    def update_local_port_engress_data(port_id):
        global egress_queue_length_register,local_port_engress_data
        if port_id<=0:
            return
        register_text_json = egress_queue_length_register.dump(json=True, from_hw=True)
        register_text = json.loads(register_text_json)
        local_port_engress_data[port_id] = register_text[port_id]['data']['Egress.egress_queue_length_register.f1'][0]
        print ("update port %d with value %d" % (port_id, local_port_engress_data[port_id]))
    
    global p4,digest_count
    ++digest_count
    if digest_count%30 != 0:
        return 0
    for digest in msg:
        update_local_port_engress_data(digest["port"])
    return 0

#p4.pipe.IngressDeparser.digest.callback_register(local_digest_callback)



def show_res():
    global ipv4_host, ipv4_lpm
    # Final programming
    print("""
    ******************* PROGAMMING RESULTS *****************
    """)
    print ("Table ipv4_host:")
    ipv4_host.dump(from_hw=True, table=True)
    print ("Table ipv4_lpm:")
    ipv4_lpm.dump(from_hw=True, table=True)


def debug():
    global p4
    ether_type_register = p4.pipe.Ingress.ether_type_register
    ipv4_dst_addr_register = p4.pipe.Ingress.ipv4_dst_addr_register
    count_register = p4.pipe.Ingress.count_register

    ether_type_register.get(0, from_hw=True)
    ipv4_dst_addr_register.get(0, from_hw=True)
    count_register.get(0, from_hw=True)
    p4.pipe.Ingress.qp_register.get(0, from_hw=True)

