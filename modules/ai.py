import json
from openai import OpenAI
from config.config import API_KEY, BASE_URL

client = OpenAI(
    api_key=API_KEY,
    base_url=BASE_URL
)

def analyze_event(event):
    """
    Agent 核心大脑：分析安全事件，并自主决策防御动作 (Tool Calling)
    """
    raw_payload = event.get('raw_payload', '暂无底层报文数据')

    prompt = f"""
你是一名资深的网络安全攻防专家与安全运维 Agent。

【事件基础信息】
- 告警名称：{event['event']}
- 来源IP：{event['source_ip']}
- 拦截设备：{event['device']}
- 风险等级：{event['level']}

【底层原始报文 (raw_payload)】
{raw_payload}

你的任务：
1. 深度解析这段原始报文，输出 Markdown 格式的威胁情报翻译（包含攻击定性、影响评估）。
2. 根据你的解析结果，评估真实风险，并强制调用对应的防御剧本工具以应对威胁。
"""

    # 定义 Agent 可以调用的工具箱
    tools = [
        {
            "type": "function",
            "function": {
                "name": "trigger_defense_playbook",
                "description": "基于安全分析结果，触发相应的 SOAR 自动化防御剧本",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "playbook_name": {
                            "type": "string",
                            "enum": ["playbook_low_risk", "playbook_medium_risk", "playbook_high_risk"],
                            "description": "低危威胁调用 playbook_low_risk，中危调用 medium_risk，高危调用 high_risk"
                        },
                        "target_ip": {
                            "type": "string",
                            "description": "需要实施防御动作的攻击源IP"
                        }
                    },
                    "required": ["playbook_name", "target_ip"]
                }
            }
        }
    ]

    response = client.chat.completions.create(
        model="deepseek-v4-flash", # 如果您用的不是 deepseek，请确保这里的模型名称正确
        messages=[
            {
                "role": "system",
                "content": "你是专业网络安全 Agent，必须在分析完毕后主动调用防御剧本工具。"
            },
            {"role": "user", "content": prompt}
        ],
        tools=tools,
        tool_choice="auto",
        temperature=0.2
    )

    message = response.choices[0].message
    
    # 提取分析报告
    analysis_text = message.content if message.content else "Agent 已完成思考：威胁特征明确，直接下发调度指令。"

    # 解析 Agent 的工具调用意图
    agent_decision = None
    if message.tool_calls:
        tool_call = message.tool_calls[0]
        if tool_call.function.name == "trigger_defense_playbook":
            try:
                agent_decision = json.loads(tool_call.function.arguments)
            except json.JSONDecodeError:
                pass

    # 这里的 return 必须返回两个变量，以匹配 app.py 的拆包需求
    return analysis_text, agent_decision