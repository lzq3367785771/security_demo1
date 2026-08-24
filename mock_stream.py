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

print(f"开始向 {log_file} 注入动态日志流...")

while True:
    rand_ip = random.choice(ips)
    rand_device = random.choice(devices)
    rand_event = random.choice(events)
    rand_level = random.choice(levels)
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 模拟原始生涩的网络报文/日志特征 (为下一步AI翻译做准备)
    raw_payload = ""
    if rand_event == "SQL注入攻击":
        raw_payload = "GET /api/user?id=1%27%20OR%201=1-- HTTP/1.1\nHost: target.com\nUser-Agent: sqlmap/1.5.8"
    elif rand_event == "异常登录":
        raw_payload = f"sshd[12345]: Failed password for root from {rand_ip} port 49201 ssh2"
    else:
        raw_payload = "0x0000: 4500 003c 1c46 4000 4006 b1e6 c0a8 0164 ...<."

    # 构建字典数据
    log_entry = {
        "time": current_time,
        "event": rand_event,
        "source_ip": rand_ip,
        "device": rand_device,
        "level": rand_level,
        "description": "设备探针检测到异常流量行为",
        "raw_payload": raw_payload
    }

    # 以 JSONL 格式（单行 JSON）追加到文件
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        
    print(f"[+] 已生成日志: {rand_event} from {rand_ip}")
    
    # 随机休眠 2-5 秒
    time.sleep(random.randint(10, 20))