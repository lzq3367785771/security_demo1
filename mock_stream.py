import json
import time
import random
import os
from datetime import datetime

os.makedirs("data", exist_ok=True)
log_file = os.path.join("data", "dynamic_logs.jsonl")

ips = ["10.10.1.25", "8.8.8.8", "172.16.1.50", "192.168.1.100", "45.33.2.19"]
devices = ["WAF", "堡垒机", "IDS/IPS", "流量探针"]

# ==========================================================
# 新增对照组：专门用于测试马氏距离 (Mahalanobis) 的协方差边界
# ==========================================================
events = ["SQL注入攻击", "异常登录", "端口扫描", "XSS跨站脚本", "DDoS流量激增", "大促业务峰值", "慢速隐蔽探测"]

print(f"开始向 {log_file} 注入动态日志流 (已加载马氏边界测试用例)...")

while True:
    rand_ip = random.choice(ips)
    rand_device = random.choice(devices)
    rand_event = random.choice(events)
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    raw_payload = "0x0000: 4500 003c 1c46 4000 4006 b1e6 c0a8 0164 ...<."
    
    # 基础语义攻击依然设定为低危，用于测试正则防线
    if rand_event == "SQL注入攻击":
        raw_payload = "GET /api/user?id=1%27%20OR%201=1-- HTTP/1.1\nHost: target.com\nUser-Agent: sqlmap/1.5.8"
        rand_level = "低危"
    elif rand_event == "异常登录":
        raw_payload = f"sshd[12345]: Failed password for root from {rand_ip} port 49201 ssh2"
        rand_level = "低危"
    elif rand_event == "XSS跨站脚本":
        raw_payload = "GET /search?q=<script>alert(1)</script> HTTP/1.1"
        rand_level = "低危"
    else:
        rand_level = random.choice(["中危", "高危"])

    if rand_event == "端口扫描":
        conn_freq = random.randint(500, 2000)
        packet_size = random.randint(40, 60)
        error_rate = round(random.uniform(0.7, 0.95), 2)
        
    elif rand_event == "DDoS流量激增":
        conn_freq = random.randint(5000, 15000)
        packet_size = random.randint(64, 1500)
        error_rate = round(random.uniform(0.4, 0.8), 2)
        
    elif rand_event in ["SQL注入攻击", "XSS跨站脚本"]:
        conn_freq = random.randint(10, 50)
        packet_size = random.randint(800, 2500)
        error_rate = round(random.uniform(0.05, 0.2), 2)
        
    elif rand_event == "异常登录":
        conn_freq = random.randint(5, 20)
        packet_size = random.randint(100, 300)
        error_rate = round(random.uniform(0.6, 1.0), 2)
        
    # ----------------------------------------------------------
    # 对照组 1：沿协方差主轴外推的“安全噪声”
    # ----------------------------------------------------------
    elif rand_event == "大促业务峰值":
        # 频率和包大小都很高，但严格服从预期的线性回归分布
        conn_freq = random.randint(65, 80)
        packet_size = int(conn_freq * 25 + random.randint(-30, 30))
        error_rate = round(random.uniform(0.01, 0.05), 2)
        rand_level = "低危"
        
    # ----------------------------------------------------------
    # 对照组 2：正交于主轴的“隐蔽离群点”
    # ----------------------------------------------------------
    else: # 慢速隐蔽探测
        # 破坏了数据结构：极低的连接频率，却对应了反常的大包
        conn_freq = random.randint(15, 20)
        packet_size = random.randint(1400, 1500) 
        error_rate = round(random.uniform(0.01, 0.05), 2)
        rand_level = "中危"
        raw_payload = "GET /api/v1/probe?data=...[大量混淆探测字节]... HTTP/1.1"

    log_entry = {
        "time": current_time,
        "event": rand_event,
        "source_ip": rand_ip,
        "device": rand_device,
        "level": rand_level,
        "description": "设备探针检测到流量行为",
        "raw_payload": raw_payload,
        "features": {
            "conn_freq": conn_freq,
            "packet_size": packet_size,
            "error_rate": error_rate
        }
    }

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        
    print(f"[+] {rand_event} | 频率: {conn_freq} | 包: {packet_size} | 错: {error_rate}")
    time.sleep(random.randint(1, 2))