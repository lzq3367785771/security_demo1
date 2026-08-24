import time

# 核心资产白名单（网关、DNS、核心业务服务器、合法扫描器等）
WHITELIST_IPS = ["8.8.8.8", "192.168.1.1", "10.10.1.254"]

# ==========================
# 1. SOAR 剧本库 (Playbooks)
# ==========================
# 剧本封装了针对不同场景的具体操作步骤（这里用 time.sleep 模拟 API 调用的耗时）

def playbook_low_risk(alarm, target_ip):
    """
    低危剧本：仅记录并持续观察，打上威胁标签，不直接阻断业务
    """
    time.sleep(0.5)
    return {
        "action": "标记并持续监控",
        "target": target_ip,
        "device": "流量探针 / 日志中心",
        "status": "执行成功 (威胁等级低，已记录入黑基线)"
    }

def playbook_medium_risk(alarm, target_ip):
    """
    中危剧本：在边界设备执行封禁，并发送普通告警通知
    """
    time.sleep(1)
    return {
        "action": "常规封禁源IP",
        "target": target_ip,
        "device": "边界防火墙",
        "status": "执行成功 (已阻断该IP的后续连接)"
    }

def playbook_high_risk(alarm, target_ip):
    """
    高危剧本：多设备联动深度隔离，并触发紧急响应预案
    """
    time.sleep(1.5)
    return {
        "action": "跨设备联合封禁与隔离",
        "target": target_ip,
        "device": "边界防火墙 + WAF + 核心交换机",
        "status": "执行成功 (已全面切断该IP网络访问，自动拉起应急预案)"
    }

# ==========================
# 2. 剧本路由中枢 (Router)
# ==========================

def playbook_router(alarm, target_ip):
    """
    根据安全事件的风险等级、资产价值等上下文，动态调度对应的响应剧本
    """
    level = alarm.get("level", "低危")
    
    if level == "高危":
        return playbook_high_risk(alarm, target_ip)
    elif level == "中危":
        return playbook_medium_risk(alarm, target_ip)
    else:
        return playbook_low_risk(alarm, target_ip)

# ==========================
# 3. 主执行入口
# ==========================

def execute_action(alarm, agent_playbook=None):
    """
    自动化响应主入口，支持接收 Agent 的自主调度指令
    """
    source_ip = alarm.get("source_ip", "")

    # 3.1 自动化前置校验：白名单检查 (合规底线，凌驾于 Agent 决策之上)
    if source_ip in WHITELIST_IPS:
        return {
            "action": "拒绝执行编排",
            "target": source_ip,
            "device": "SOC中控台",
            "status": "校验拦截 (命中核心资产白名单，动作中止)"
        }

    # 3.2 如果 Agent 明确指定了剧本，则优先执行 Agent 的决策
    if agent_playbook == "playbook_high_risk":
        result = playbook_high_risk(alarm, source_ip)
    elif agent_playbook == "playbook_medium_risk":
        result = playbook_medium_risk(alarm, source_ip)
    elif agent_playbook == "playbook_low_risk":
        result = playbook_low_risk(alarm, source_ip)
    else:
        # 如果 Agent 未指定，退化为按原有规则静态路由
        result = playbook_router(alarm, source_ip)
    
    return result