import streamlit as st
import pandas as pd
import json
import os


from modules.device import get_device_status
from modules.alarm import get_alarm_list
from modules.ai import analyze_event
from modules.action import execute_action
from modules.audit import save_audit



# ==========================
# 页面配置
# ==========================

st.set_page_config(
    page_title="网络安全智能运维平台",
    layout="wide"
)



# ==========================
# 侧边栏
# ==========================

st.sidebar.title(
    "AI安全运维助手"
)


st.sidebar.info(
"""
系统能力：

✓ 安全设备监控

✓ 安全告警分析

✓ AI日志解析

✓ 自动化响应

✓ 安全审计闭环

"""
)



# ==========================
# 标题
# ==========================

st.title(
    "网络安全自动化智能运维系统 Demo"
)



# ==========================
# 获取数据
# ==========================

devices = get_device_status()

alarms = get_alarm_list()



# ==========================
# 一、安全态势总览
# ==========================

st.subheader(
    "安全态势总览"
)



device_count = len(devices)


online_count = len(
    [
        d for d in devices
        if d["status"] == "在线"
    ]
)


alarm_count = len(alarms)


high_risk = len(
    [
        a for a in alarms
        if a["level"] == "高危"
    ]
)



col1, col2, col3, col4 = st.columns(4)



with col1:

    st.metric(
        "安全设备数量",
        device_count
    )



with col2:

    st.metric(
        "在线设备",
        online_count
    )



with col3:

    st.metric(
        "当前告警",
        alarm_count
    )



with col4:

    st.metric(
        "高危事件",
        high_risk
    )





# ==========================
# 二、安全设备状态
# ==========================

st.header(
    "一、安全设备状态"
)



df = pd.DataFrame(devices)



st.dataframe(
    df,
    use_container_width=True
)




# ==========================
# 三、安全告警中心
# ==========================

st.header(
    "二、安全告警中心"
)



for alarm in alarms:


    title = (
        f"{alarm['level']} - {alarm['event']}"
    )



    # 风险等级颜色显示

    if alarm["level"] == "高危":

        st.error(title)


    elif alarm["level"] == "中危":

        st.warning(title)


    else:

        st.info(title)



    # 展开详情

    with st.expander(
        "查看事件详情"
    ):



        st.write(
            "来源IP：",
            alarm["source_ip"]
        )


        st.write(
            "攻击设备：",
            alarm["device"]
        )


        st.write(
            "发生时间：",
            alarm["time"]
        )


        st.write(
            "事件描述：",
            alarm["description"]
        )



        st.divider()



        # AI分析按钮

        if st.button(
            f"AI研判：{alarm['event']}",
            key=f"ai_{alarm['event']}"
        ):


            with st.spinner(
                "AI正在分析安全事件..."
            ):


                result = analyze_event(alarm)



            st.info(result)




        # 自动处理按钮

        if st.button(
            f"自动处理：{alarm['event']}",
            key=f"action_{alarm['event']}"
        ):


            with st.spinner(
                "正在执行自动化响应..."
            ):



                action_result = execute_action(
                    alarm
                )



            # 保存审计记录

            save_audit(
                alarm,
                action_result,
                "AI分析完成"
            )



            st.success(
f"""
自动化处理完成！


动作：
{action_result['action']}


目标：
{action_result['target']}


设备：
{action_result['device']}


状态：
{action_result['status']}

"""
            )





# ==========================
# 四、安全审计记录
# ==========================

st.header(
    "三、安全审计记录"
)



audit_path = os.path.join(
    "data",
    "audit.json"
)



if os.path.exists(audit_path):


    with open(
        audit_path,
        "r",
        encoding="utf-8"
    ) as f:

        records = json.load(f)



    for record in records:


        st.info(
f"""
事件编号：
{record['event_id']}


时间：
{record['time']}


事件：
{record['event']}


来源IP：
{record['source_ip']}


执行动作：
{record['action']}


处理结果：
{record['result']}

"""
        )


else:


    st.info(
        "暂无安全审计记录"
    )