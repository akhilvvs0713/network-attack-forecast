import csv
import random
from datetime import datetime, timedelta

def get_row(attack_type, start_time):
    # Base row (normal)
    row = {
        'src_ip': '192.168.1.10',
        'dst_ip': '172.217.116.4',
        'src_port': random.randint(1024, 65535),
        'dst_port': 443,
        'protocol': 6,
        'timestamp': start_time.strftime('%Y-%m-%d %H:%M:%S'),
        'flow_duration': random.uniform(0.1, 100.0),
        'flow_byts_s': random.uniform(10, 10000),
        'flow_pkts_s': random.uniform(0.1, 500),
        'fwd_pkts_s': random.uniform(0.1, 250),
        'bwd_pkts_s': random.uniform(0.1, 250),
        'tot_fwd_pkts': random.randint(5, 50),
        'tot_bwd_pkts': random.randint(5, 50),
        'totlen_fwd_pkts': random.randint(300, 5000),
        'totlen_bwd_pkts': random.randint(300, 50000),
        'fwd_pkt_len_max': random.randint(66, 1500),
        'fwd_pkt_len_min': 66,
        'fwd_pkt_len_mean': random.uniform(66, 300),
        'fwd_pkt_len_std': random.uniform(10, 200),
        'bwd_pkt_len_max': random.randint(66, 1500),
        'bwd_pkt_len_min': 66,
        'bwd_pkt_len_mean': random.uniform(66, 1000),
        'bwd_pkt_len_std': random.uniform(10, 500),
        'pkt_len_max': random.randint(66, 1500),
        'pkt_len_min': 66,
        'pkt_len_mean': random.uniform(66, 800),
        'pkt_len_std': random.uniform(10, 400),
        'pkt_len_var': random.uniform(100, 160000),
        'fwd_header_len': 20,
        'bwd_header_len': 20,
        'fwd_seg_size_min': 20,
        'fwd_act_data_pkts': random.randint(1, 40),
        'flow_iat_mean': random.uniform(0.01, 5.0),
        'flow_iat_max': random.uniform(1.0, 30.0),
        'flow_iat_min': 0.0,
        'flow_iat_std': random.uniform(0.1, 10.0),
        'fwd_iat_tot': random.uniform(0.1, 100.0),
        'fwd_iat_max': random.uniform(1.0, 30.0),
        'fwd_iat_min': 0.0,
        'fwd_iat_mean': random.uniform(0.01, 5.0),
        'fwd_iat_std': random.uniform(0.1, 10.0),
        'bwd_iat_tot': random.uniform(0.1, 100.0),
        'bwd_iat_max': random.uniform(1.0, 30.0),
        'bwd_iat_min': 0.0,
        'bwd_iat_mean': random.uniform(0.01, 5.0),
        'bwd_iat_std': random.uniform(0.1, 10.0),
        'fwd_psh_flags': random.randint(0, 1),
        'bwd_psh_flags': random.randint(0, 1),
        'fwd_urg_flags': 0,
        'bwd_urg_flags': 0,
        'fin_flag_cnt': random.randint(0, 1),
        'syn_flag_cnt': random.randint(0, 2),
        'rst_flag_cnt': random.randint(0, 1),
        'psh_flag_cnt': random.randint(0, 10),
        'ack_flag_cnt': random.randint(2, 50),
        'urg_flag_cnt': 0,
        'ece_flag_cnt': 0,
        'down_up_ratio': random.uniform(0.5, 2.0),
        'pkt_size_avg': random.uniform(66, 800),
        'init_fwd_win_byts': random.randint(1000, 65535),
        'init_bwd_win_byts': random.randint(1000, 65535),
        'active_max': 0,
        'active_min': 0,
        'active_mean': 0,
        'active_std': 0,
        'idle_max': 0,
        'idle_min': 0,
        'idle_mean': 0,
        'idle_std': 0,
        'fwd_byts_b_avg': 0,
        'fwd_pkts_b_avg': 0,
        'bwd_byts_b_avg': 0,
        'bwd_pkts_b_avg': 0,
        'fwd_blk_rate_avg': 0,
        'bwd_blk_rate_avg': 0,
        'fwd_seg_size_avg': random.uniform(66, 300),
        'bwd_seg_size_avg': random.uniform(66, 1000),
        'cwr_flag_count': 0,
        'subflow_fwd_pkts': random.randint(5, 50),
        'subflow_bwd_pkts': random.randint(5, 50),
        'subflow_fwd_byts': random.randint(300, 5000),
        'subflow_bwd_byts': random.randint(300, 50000)
    }

    if attack_type == 'SYN_Flood':
        row.update({
            'src_ip': f'10.0.0.{random.randint(1,250)}',
            'dst_ip': '192.168.1.100',
            'flow_duration': random.uniform(0.000001, 0.0001),
            'tot_fwd_pkts': random.randint(1, 3),
            'tot_bwd_pkts': 0,
            'fwd_pkt_len_max': 60,
            'fwd_pkt_len_min': 60,
            'fwd_pkt_len_mean': 60,
            'fwd_pkt_len_std': 0,
            'bwd_pkt_len_max': 0,
            'bwd_pkt_len_min': 0,
            'bwd_pkt_len_mean': 0,
            'bwd_pkt_len_std': 0,
            'syn_flag_cnt': random.randint(1, 3),
            'ack_flag_cnt': 0,
            'bwd_pkts_s': 0,
            'totlen_bwd_pkts': 0,
            'down_up_ratio': 0,
        })
    elif attack_type == 'Port_Scan':
        row.update({
            'src_ip': '10.10.10.11',
            'dst_ip': '192.168.1.100',
            'dst_port': random.choice([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389]),
            'flow_duration': random.uniform(0.0001, 0.01),
            'tot_fwd_pkts': 1,
            'tot_bwd_pkts': 1,
            'syn_flag_cnt': 1,
            'rst_flag_cnt': 1,
            'totlen_fwd_pkts': 60,
            'totlen_bwd_pkts': 60,
            'fwd_pkt_len_max': 60,
            'fwd_pkt_len_min': 60,
            'fwd_pkt_len_mean': 60,
            'bwd_pkt_len_max': 60,
            'bwd_pkt_len_min': 60,
            'bwd_pkt_len_mean': 60,
            'down_up_ratio': 1,
        })
    elif attack_type == 'Brute_Force':
        row.update({
            'src_ip': '10.10.10.12',
            'dst_ip': '192.168.1.100',
            'dst_port': 22,
            'flow_duration': random.uniform(2.0, 10.0),
            'tot_fwd_pkts': random.randint(20, 40),
            'tot_bwd_pkts': random.randint(20, 40),
            'syn_flag_cnt': 1,
            'ack_flag_cnt': random.randint(40, 80),
            'fwd_pkt_len_mean': random.uniform(80, 150),
            'bwd_pkt_len_mean': random.uniform(100, 200),
            'down_up_ratio': random.uniform(0.8, 1.2),
        })

    return row

columns = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp", "flow_duration",
    "flow_byts_s", "flow_pkts_s", "fwd_pkts_s", "bwd_pkts_s", "tot_fwd_pkts", "tot_bwd_pkts",
    "totlen_fwd_pkts", "totlen_bwd_pkts", "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean",
    "fwd_pkt_len_std", "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "pkt_len_max", "pkt_len_min", "pkt_len_mean", "pkt_len_std", "pkt_len_var", "fwd_header_len",
    "bwd_header_len", "fwd_seg_size_min", "fwd_act_data_pkts", "flow_iat_mean", "flow_iat_max",
    "flow_iat_min", "flow_iat_std", "fwd_iat_tot", "fwd_iat_max", "fwd_iat_min", "fwd_iat_mean",
    "fwd_iat_std", "bwd_iat_tot", "bwd_iat_max", "bwd_iat_min", "bwd_iat_mean", "bwd_iat_std",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags", "fin_flag_cnt", "syn_flag_cnt",
    "rst_flag_cnt", "psh_flag_cnt", "ack_flag_cnt", "urg_flag_cnt", "ece_flag_cnt", "down_up_ratio",
    "pkt_size_avg", "init_fwd_win_byts", "init_bwd_win_byts", "active_max", "active_min", "active_mean",
    "active_std", "idle_max", "idle_min", "idle_mean", "idle_std", "fwd_byts_b_avg", "fwd_pkts_b_avg",
    "bwd_byts_b_avg", "bwd_pkts_b_avg", "fwd_blk_rate_avg", "bwd_blk_rate_avg", "fwd_seg_size_avg",
    "bwd_seg_size_avg", "cwr_flag_count", "subflow_fwd_pkts", "subflow_bwd_pkts", "subflow_fwd_byts",
    "subflow_bwd_byts"
]

with open('fabricated_attacks.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=columns)
    writer.writeheader()
    
    start_time = datetime(2026, 9, 11, 10, 0, 0)
    
    # Generate Normal traffic
    for _ in range(100):
        writer.writerow(get_row('Normal', start_time))
        start_time += timedelta(seconds=random.uniform(0.1, 5.0))
        
    # Generate SYN Flood
    for _ in range(50):
        writer.writerow(get_row('SYN_Flood', start_time))
        start_time += timedelta(microseconds=random.randint(1, 100))
        
    # Generate Port Scan
    for _ in range(50):
        writer.writerow(get_row('Port_Scan', start_time))
        start_time += timedelta(milliseconds=random.randint(1, 50))
        
    # Generate Brute Force
    for _ in range(50):
        writer.writerow(get_row('Brute_Force', start_time))
        start_time += timedelta(seconds=random.uniform(1.0, 10.0))

print("Created fabricated_attacks.csv successfully.")
