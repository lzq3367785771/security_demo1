import json
from openai import OpenAI
from config.config import API_KEY, BASE_URL

client = OpenAI(
    api_key=API_KEY,
    base_url=BASE_URL
)

def analyze_event(event, ml_result=None):
    """
    Agent 核心大脑：分析安全事件，结合机器学习初筛结果进行情报融合，并自主决策防御动作
    """
    raw_payload = event.get('raw_payload', '暂无底层报文数据')
    
    # 构建机器学习情报上下文
    ml_context = "暂无机器学习前置分析数据。"
    if ml_result:
        is_mal_str = "异常/恶意流量" if ml_result['is_malicious'] else "正常流量"
        ml_context = f"判定结果：[{is_mal_str}]，置信度：[{ml_result['confidence']}%]"

    prompt = f"""
你是一名资深的网络安全攻防专家与安全运维 Agent。

【事件基础信息】
- 告警名称：{event.get('event', '未知')}
- 来源IP：{event.get('source_ip', '未知')}
- 拦截设备：{event.get('device', '未知')}
- 风险等级：{event.get('level', '未知')}

【前置机器学习引擎初判结果】
{ml_context}

【底层原始报文 (raw_payload)】
{raw_payload}

你的任务：
1. 深度解析这段原始报文，输出 Markdown 格式的威胁情报翻译。
2. 特别要求：在报告中加入【情报融合研判】章节。你需要对比“前置机器学习的判定结果”与“你解析出的真实语义”。
   - 如果机器学习判断正确，请解释其统计特征为何生效。
   - 如果机器学习判断错误（例如漏报了隐蔽的 SQL 注入），请以高级安全专家的口吻解释：为什么传统的统计学分类器会看漏，而你的深度包检测（DPI）发现了真实威胁，并给出纠偏结论。
3. 根据你的最终综合解析结果，评估真实风险，并强制调用对应的防御剧本工具以应对威胁。
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
                            "description": "低危调用 playbook_low_risk，中危调用 medium_risk，高危调用 high_risk"
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
        model="deepseek-v4-flash", 
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
    
    analysis_text = message.content if message.content else "Agent 已完成思考：威胁特征明确，直接下发调度指令。"

    agent_decision = None
    if message.tool_calls:
        tool_call = message.tool_calls[0]
        if tool_call.function.name == "trigger_defense_playbook":
            try:
                agent_decision = json.loads(tool_call.function.arguments)
            except json.JSONDecodeError:
                pass

    return analysis_text, agent_decision