import time


def execute_action(alarm):
    """
    模拟安全设备自动响应

    后续可以替换为：
    防火墙API
    WAF API
    SOAR接口
    """

    result = {}

    # 获取攻击源IP
    source_ip = alarm["source_ip"]


    # 模拟调用设备
    time.sleep(1)


    result = {

        "action":
        "封禁攻击IP",

        "target":
        source_ip,

        "device":
        "防火墙",

        "status":
        "执行成功"

    }


    return result