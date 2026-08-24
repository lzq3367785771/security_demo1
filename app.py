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

st.header("二、安全告警中心")

# 修改点 1：使用 enumerate 获取唯一索引 idx
for idx, alarm in enumerate(alarms):

    title = f"{alarm['level']} - {alarm['event']}"

    # 风险等级颜色显示
    if alarm["level"] == "高危":
        st.error(title)
    elif alarm["level"] == "中危":
        st.warning(title)
    else:
        st.info(title)

    # 展开详情
    with st.expander("查看事件详情"):
        st.write("来源IP：", alarm["source_ip"])
        st.write("攻击设备：", alarm["device"])
        st.write("发生时间：", alarm["time"])
        st.write("事件描述：", alarm["description"])
        
        # 新增点：展示我们刚才在 mock_stream 中生成的底层原始报文
        if "raw_payload" in alarm:
            st.write("原始报文：")
            st.code(alarm["raw_payload"])

        st.divider()

 # ===============================
        # 终极形态：Agent 自主协同闭环
        # ===============================
        if st.button(f"🤖 Agent 自主研判与处置", key=f"agent_{idx}_{alarm['event']}"):
            
            # 第一阶段：AI 思考与翻译
            with st.spinner("🧠 Agent 正在深度解析底层报文并规划 SOAR 剧本..."):
                analysis_text, agent_decision = analyze_event(alarm)

            st.markdown("### 📋 Agent 威胁解析报告")
            st.info(analysis_text)
            st.divider()

            # 第二阶段：Agent 自主执行决策
            if agent_decision:
                st.markdown("### ⚡ Agent 编排指令执行")
                playbook_to_run = agent_decision.get("playbook_name")
                
                st.write(f"**调度意图**：准备对目标IP `{agent_decision.get('target_ip')}` 发起 `{playbook_to_run}`。")
                
                with st.spinner("🛡️ 系统底层正在进行合规校验与物理设备联动..."):
                    # 将 Agent 指定的剧本传给动作执行器
                    action_result = execute_action(alarm, playbook_to_run)

                # 保存审计记录 (将 Agent 的思考链一并存入合规库)
                save_audit(alarm, action_result, f"由Agent自主触发: {playbook_to_run}")

                # 第三阶段：校验拦截反馈
                if "校验拦截" in action_result["status"]:
                    st.warning(
                        f"""
                        ⚠️ **合规前置拦截触发**
                        
                        动作：{action_result['action']}
                        目标：{action_result['target']}
                        状态：{action_result['status']}
                        
                        **系统评价**：Agent 下发了封禁指令，但由于该 IP 属于白名单核心资产，系统底层拦截了该动作，防止了自杀式阻断。
                        """
                    )
                else:
                    st.success(
                        f"""
                        ✅ **自动化闭环完成**

                        动作：{action_result['action']}
                        目标：{action_result['target']}
                        联动设备：{action_result['device']}
                        状态：{action_result['status']}
                        """
                    )
            else:
                st.warning("Agent 进行了分析，但认为无需调用自动化防御动作，或工具调用失败。")

# ==========================
# 四、安全审计记录
# ==========================

st.header("三、安全审计记录")

audit_path = os.path.join("data", "audit.json")

if os.path.exists(audit_path):
    with open(audit_path, "r", encoding="utf-8") as f:
        try:
            records = json.load(f)
        except json.JSONDecodeError:
            records = []

    if records:
        # 将结构化数据转为 DataFrame，这在进行大量数据统计展示时更加高效直观
        audit_df = pd.DataFrame(records)
        
        # 将时间列转换为时间格式，并执行降序排列（确保最新执行的阻断动作显示在最顶端）
        audit_df["time"] = pd.to_datetime(audit_df["time"])
        audit_df = audit_df.sort_values(by="time", ascending=False)
        
        # 将时间重新格式化为字符串以保持 UI 美观
        audit_df["time"] = audit_df["time"].dt.strftime("%Y-%m-%d %H:%M:%S")

        # 增加一个数据筛选器，联动展示不同状态的审计记录
        status_options = ["全部"] + list(audit_df["result"].unique())
        selected_status = st.selectbox("按处理状态筛选:", status_options)

        # 联动过滤逻辑
        if selected_status != "全部":
            audit_df = audit_df[audit_df["result"] == selected_status]

        # 挑选关键列并重命名，屏蔽掉不需要前端展示的冗余字段
        display_df = audit_df[["time", "event_id", "event", "source_ip", "device", "action", "result"]]
        display_df.columns = ["操作时间", "事件编号", "告警事件", "来源IP", "联动设备", "执行动作", "处理结果"]

        # 渲染交互式表格
        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("当前审计文件为空，尚未产生自动化处理记录。")
else:
    st.info("暂无安全审计记录。")