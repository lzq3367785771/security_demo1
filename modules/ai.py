from openai import OpenAI

from config.config import API_KEY, BASE_URL



client = OpenAI(
    api_key=API_KEY,
    base_url=BASE_URL
)



def analyze_event(event):

    """
    调用大模型分析安全事件
    """


    prompt = f"""

你是一名网络安全专家。

请分析下面安全事件：

事件：
{event['event']}

来源IP：
{event['source_ip']}

设备：
{event['device']}

日志描述：
{event['description']}


请输出：

1. 攻击类型
2. 风险分析
3. 攻击原因
4. 潜在影响
5. 处理建议


注意：
系统已经给出了事件风险等级：
{event['level']}

请不要修改该等级。

请基于该等级进行解释。

要求：
使用中文回答。

"""


    response = client.chat.completions.create(

        model="deepseek-v4-flash",

        messages=[

            {
                "role": "system",
                "content":
                "你是专业网络安全分析专家"
            },

            {
                "role":"user",
                "content":prompt
            }

        ],

        temperature=0.3

    )


    result = response.choices[0].message.content


    return result