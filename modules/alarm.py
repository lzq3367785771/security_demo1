import json
import os

def get_alarm_list(limit=20):
    """
    从动态安全日志流读取告警
    读取 .jsonl 格式文件，并返回最新的 limit 条记录供前端展示
    """

    file_path = os.path.join(
        "data",
        "dynamic_logs.jsonl"
    )

    # 如果系统刚启动，日志流文件还未生成，返回空列表
    if not os.path.exists(file_path):
        return []

    alarms = []
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:  # 忽略空行
                    try:
                        alarm_data = json.loads(line)
                        alarms.append(alarm_data)
                    except json.JSONDecodeError:
                        continue # 容错处理：跳过损坏的日志行
                        
    except Exception as e:
        print(f"读取日志流异常: {e}")
        return []

    # 截取最新的 N 条记录，并倒序排列（最新发生的在最前面展示）
    latest_alarms = alarms[-limit:]
    latest_alarms.reverse()
    
    return latest_alarms