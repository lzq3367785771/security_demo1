import json
import time
import random
import os
from datetime import datetime

# 确保 data 目录存在
os.makedirs("data", exist_ok=True)
log_file = os.path.join("data", "dynamic_logs.jsonl")

# 定义模拟数据的数组
ips = ["10.10.1.25", "8.8.8.8", "172.16.1.50", "192.168.1.100", "45.33.2.19"]
devices = ["WAF", "堡垒机", "IDS/IPS", "流量探针"]
events = ["SQL注入攻击", "异常登录", "端口扫描", "XSS跨站脚本", "DDoS流量激增"]
levels = ["高危", "中危", "低危"]

print(f"开始向 {log_file} 注入带有数值型特征的动态日志流...")

while True:
    rand_ip = random.choice(ips)
    rand_device = random.choice(devices)
    rand_event = random.choice(events)
    rand_level = random.choice(levels)
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. 模拟原始生涩的网络报文/日志特征
    raw_payload = ""
    if rand_event == "SQL注入攻击":
        raw_payload = "GET /api/user?id=1%27%20OR%201=1-- HTTP/1.1\nHost: target.com\nUser-Agent: sqlmap/1.5.8"
    elif rand_event == "异常登录":
        raw_payload = f"sshd[12345]: Failed password for root from {rand_ip} port 49201 ssh2"
    else:
        raw_payload = "0x0000: 4500 003c 1c46 4000 4006 b1e6 c0a8 0164 ...<."

    # ==========================================================
    # 2. 核心修改：根据不同的攻击类型，注入具有物理规律的数值型特征
    # 这将作为后续 KNN 分类器和 SHAP 归因的训练/推理依据
    # ==========================================================
    if rand_event == "端口扫描":
        conn_freq = random.randint(500, 2000)            # 扫描时连接频率极高
        packet_size = random.randint(40, 60)             # 通常是小包 (如 SYN 探测包)
        error_rate = round(random.uniform(0.7, 0.95), 2) # 大量端口未开放导致极高的错误/拒绝率
        
    elif rand_event == "DDoS流量激增":
        conn_freq = random.randint(5000, 15000)          # 极端的连接并发频率
        packet_size = random.randint(64, 1500)           # 混合包大小
        error_rate = round(random.uniform(0.4, 0.8), 2)  # 目标服务拥塞产生大量丢包或错误
        
    elif rand_event in ["SQL注入攻击", "XSS跨站脚本"]:
        conn_freq = random.randint(10, 50)               # 请求频率与正常用户相近，不易触发速率限制
        packet_size = random.randint(800, 2500)          # HTTP报文包含长恶意 Payload，体积较大
        error_rate = round(random.uniform(0.05, 0.2), 2) # 错误率较低
        
    else: # 异常登录
        conn_freq = random.randint(5, 20)                # 密码爆破频率
        packet_size = random.randint(100, 300)           # 登录鉴权包大小中等
        error_rate = round(random.uniform(0.6, 1.0), 2)  # 认证失败率极高

    # 构建字典数据，新增 features 嵌套字段
    log_entry = {
        "time": current_time,
        "event": rand_event,
        "source_ip": rand_ip,
        "device": rand_device,
        "level": rand_level,
        "description": "设备探针检测到异常流量行为",
        "raw_payload": raw_payload,
        "features": {
            "conn_freq": conn_freq,
            "packet_size": packet_size,
            "error_rate": error_rate
        }
    }

    # 以 JSONL 格式（单行 JSON）追加到文件
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        
    print(f"[+] 已生成特征日志: {rand_event} | 频率: {conn_freq}/s | 包大小: {packet_size}B | 错误率: {error_rate}")
    
    # 随机休眠 2-5 秒
    time.sleep(random.randint(2, 5))