import streamlit as st
import pandas as pd
import json
import os
import shap
import matplotlib.pyplot as plt
import numpy as np
import re

from modules.device import get_device_status
from modules.alarm import get_alarm_list
from modules.ai import analyze_event
from modules.action import execute_action
from modules.audit import save_audit
from modules.ml_engine import ml_engine

# ==========================
# 页面配置
# ==========================
st.set_page_config(page_title="网络安全智能运维平台", layout="wide")

# ==========================
# 正则规则引擎 (兜底语义攻击)
# ==========================
def check_payload_rules(payload):
    """
    匹配底层报文是否包含已知的攻击语义指纹
    """
    if not payload:
        return False, None
        
    rules = {
        "SQL注入指纹 (SQLi)": r"(?i)(sqlmap|1=1|select\s+.*from|union\s+select|'%20OR|' OR)",
        "XSS跨站脚本 (XSS)": r"(?i)(<script.*?>|javascript:|onerror=)",
        "敏感目录遍历 (LFI)": r"(?i)(\.\./\.\./|/etc/passwd|win\.ini)"
    }
    
    for rule_name, pattern in rules.items():
        if re.search(pattern, payload):
            return True, rule_name
            
    return False, None

# ==========================
# 侧边栏菜单路由
# ==========================
st.sidebar.title("🛡️ AI安全运维助手")
menu = st.sidebar.radio(
    "📍 系统导航菜单",
    ["一、设备与态势总览", "二、安全告警中心", "三、安全审计记录"]
)

st.sidebar.divider()
st.sidebar.info("系统能力：\n\n✓ 安全设备监控\n\n✓ 正则规则过滤\n\n✓ 机器学习初筛\n\n✓ Agent自主研判\n\n✓ 自动化响应编排")

st.title("网络安全自动化智能运维系统 Demo")

# ==========================
# 获取底层数据
# ==========================
devices = get_device_status()
alarms = get_alarm_list(50) 

# ====================================================================
# 路由页面一：设备与态势总览
# ====================================================================
if menu == "一、设备与态势总览":
    st.subheader("安全态势总览")
    
    device_count = len(devices)
    online_count = len([d for d in devices if d["status"] == "在线"])
    alarm_count = len(alarms)
    high_risk = len([a for a in alarms if a["level"] == "高危"])

    col1, col2, col3, col4 = st.columns(4)
    with col1: st.metric("安全设备数量", device_count)
    with col2: st.metric("在线设备", online_count)
    with col3: st.metric("当前告警", alarm_count)
    with col4: st.metric("高危事件", high_risk)

    st.header("安全设备状态")
    st.dataframe(pd.DataFrame(devices), use_container_width=True)

# ====================================================================
# 路由页面二：安全告警中心
# ====================================================================
elif menu == "二、安全告警中心":
    st.header("安全告警中心")

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        btn_auto = st.button("🚀 启动全自动处置 (一键静默巡检)", type="primary", use_container_width=True)
    with col_btn2:
        btn_ml_split = st.button("🔍 ML 引擎分流 (人工审核模式)", use_container_width=True)

    st.divider()

    # -------------------------------
    # 功能一：全自动静默巡检 (融合正则+ML双引擎)
    # -------------------------------
    if btn_auto:
        my_bar = st.progress(0, text="系统正在进行全量告警自动分流与处置...")
        processed_count, skipped_count = 0, 0
        status_text = st.empty()

        for i, alarm in enumerate(alarms):
            level, event_name = alarm.get("level", "低危"), alarm.get("event", "未知")
            features = alarm.get("features", {})
            raw_payload = alarm.get("raw_payload", "")
            
            is_rule_hit, rule_name = check_payload_rules(raw_payload)
            is_malicious, conf = ml_engine.predict_traffic(features) if features else (False, 0.0)
            confidence = round(conf * 100 if is_malicious else (1 - conf) * 100, 1)

            if is_rule_hit:
                status_text.text(f"🛑 正则命中 ({rule_name})：触发 Agent 处置 {level}-{event_name}")
                should_process = True
            elif level == "低危" and not is_malicious:
                skipped_count += 1
                status_text.text(f"⏭️ 自动跳过：{level}-{event_name} (双引擎均未发现异常)")
                should_process = False
            else:
                status_text.text(f"🧠 触发 Agent：{level}-{event_name}")
                should_process = True

            if should_process:
                ml_res_dict = {"is_malicious": is_malicious, "confidence": confidence, "rule_hit": rule_name}
                analysis_text, agent_decision = analyze_event(alarm, ml_result=ml_res_dict)

                if agent_decision:
                    playbook = agent_decision.get("playbook_name")
                    action_result = execute_action(alarm, playbook)
                    save_audit(alarm, action_result, f"全自动引擎触发: {playbook}")
                processed_count += 1
                
            my_bar.progress((i + 1) / len(alarms), text=f"已巡检 {i+1}/{len(alarms)} 条告警数据...")

        status_text.empty()
        st.success(f"✅ **全自动化执行完毕！** 跳过低危噪音 **{skipped_count}** 条，Agent 拦截处置 **{processed_count}** 条。")
        st.divider()

    # -------------------------------
    # 功能二：ML 分流与人工审核 (融合正则+ML双引擎)
    # -------------------------------
    if btn_ml_split:
        st.session_state.split_done = True
        safe_noise, danger_threats = [], []
        
        for alarm in alarms:
            features = alarm.get("features", {})
            raw_payload = alarm.get("raw_payload", "")
            
            is_rule_hit, rule_name = check_payload_rules(raw_payload)
            is_malicious, _ = ml_engine.predict_traffic(features) if features else (False, 0.0)
            
            alarm["rule_hit"] = rule_name 
            
            if not is_rule_hit and alarm.get("level", "低危") == "低危" and not is_malicious:
                safe_noise.append(alarm)
            else:
                danger_threats.append(alarm)
                
        st.session_state.safe_noise = safe_noise
        st.session_state.danger_threats = danger_threats

    if st.session_state.get("split_done"):
        st.markdown("### 🗂️ ML 引擎智能分流结果面板")
        safe_list, danger_list = st.session_state.safe_noise, st.session_state.danger_threats
        
        def render_custom_table(alarms_list, list_type):
            if not alarms_list:
                st.info("暂无数据")
                return
            h1, h2, h3, h4, h5 = st.columns([3, 1, 2, 2, 2])
            h1.markdown("**时间**")
            h2.markdown("**等级**")
            h3.markdown("**告警类型**")
            h4.markdown("**来源IP**")
            h5.markdown("**操作**")
            
            with st.container(height=400):
                for idx, alarm in enumerate(alarms_list):
                    c1, c2, c3, c4, c5 = st.columns([3, 1, 2, 2, 2])
                    c1.write(alarm.get("time", ""))
                    c2.write(alarm.get("level", ""))
                    c3.write(alarm.get("event", ""))
                    c4.write(alarm.get("source_ip", ""))
                    if c5.button("🔍 查看", key=f"btn_{list_type}_{idx}"):
                        st.session_state.view_detail_alarm = alarm

        col_safe, col_danger = st.columns(2)
        with col_safe:
            st.success(f"🟢 安全噪声: {len(safe_list)} 条")
            render_custom_table(safe_list, "safe")
        with col_danger:
            st.error(f"🔴 危险告警: {len(danger_list)} 条")
            render_custom_table(danger_list, "danger")

        # 批量处理按钮 (紧跟在表格下方，仅保留一处)
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🤖 确认：将右侧危险告警批量移交 Agent 处理", type="primary"):
            my_bar = st.progress(0, text="Agent 正在批量研判并执行防御动作...")
            processed_count = 0
            status_text = st.empty()
            
            for i, alarm in enumerate(danger_list):
                status_text.text(f"🧠 Agent 正在处理：{alarm.get('level', '')}-{alarm.get('event', '')}...")
                is_malicious, conf = ml_engine.predict_traffic(alarm.get("features", {}))
                ml_res_dict = {"is_malicious": is_malicious, "confidence": round(conf * 100 if is_malicious else (1 - conf) * 100, 1), "rule_hit": alarm.get("rule_hit")}
                _, agent_decision = analyze_event(alarm, ml_result=ml_res_dict)
                
                if agent_decision:
                    playbook = agent_decision.get("playbook_name")
                    action_result = execute_action(alarm, playbook)
                    save_audit(alarm, action_result, f"人工审核后批量触发: {playbook}")
                processed_count += 1
                my_bar.progress((i + 1) / len(danger_list))
            
            status_text.empty()
            st.success(f"✅ 批量处置完毕！共处理 {processed_count} 条威胁，请前往审计记录查看。")
            st.session_state.split_done = False

        # 详情面板
        if st.session_state.get("view_detail_alarm"):
            st.markdown("---")
            st.markdown("### 🎯 快速分析详情视图")
            selected_alarm = st.session_state.view_detail_alarm
            
            with st.container(border=True):
                st.write(f"**告警类型：** {selected_alarm.get('level', '')} - {selected_alarm.get('event', '')}")
                st.write(f"**来源 IP：** {selected_alarm.get('source_ip', '')}")
                
                rule_hit = selected_alarm.get("rule_hit")
                if rule_hit:
                    st.error(f"🚨 **正则过滤网前置拦截：** 明确命中【{rule_hit}】")
                
                if "features" in selected_alarm:
                    features = selected_alarm["features"]
                    f1, f2, f3 = st.columns(3)
                    f1.metric("连接频率", features.get("conn_freq", 0))
                    f2.metric("包大小", features.get("packet_size", 0))
                    f3.metric("错误率", features.get("error_rate", 0))
                    
                    is_mal, conf = ml_engine.predict_traffic(features)
                    if is_mal: st.error(f"机器初判结果：异常/恶意流量 (置信度 {conf*100:.1f}%)")
                    else: st.success(f"机器初判结果：正常流量 (置信度 {(1-conf)*100:.1f}%)")
                
                if "raw_payload" in selected_alarm:
                    st.code(selected_alarm["raw_payload"])
                    
                st.divider()

                col_btn1, col_btn2, _ = st.columns([2, 3, 5])
                
                with col_btn1:
                    if st.button("✖️ 关闭详情", key="close_detail"):
                        st.session_state.view_detail_alarm = None
                        st.rerun()
                
                # 记录按钮的点击状态，不要在局部列(Column)内部直接渲染内容
                agent_clicked = False
                with col_btn2:
                    if st.button("🤖 交由 Agent 单独研判与处置", type="primary", key="single_agent_process"):
                        agent_clicked = True
                
                # ==========================================
                # 核心修复点：跳出 col_btn2 的狭窄列宽限制
                # 在最外层的全宽容器中进行渲染
                # ==========================================
                if agent_clicked:
                    st.divider()
                    with st.spinner("🧠 Agent 正在研判..."):
                        is_mal, conf = ml_engine.predict_traffic(selected_alarm.get("features", {}))
                        ml_res_dict = {"is_malicious": is_mal, "confidence": round(conf * 100 if is_mal else (1 - conf) * 100, 1), "rule_hit": selected_alarm.get("rule_hit")}
                        analysis_text, agent_decision = analyze_event(selected_alarm, ml_result=ml_res_dict)
                        
                    with st.container(border=True):
                        st.markdown("##### 📋 Agent 研判报告")
                        st.markdown(analysis_text)
                    
                    if agent_decision:
                        playbook = agent_decision.get("playbook_name")
                        action_result = execute_action(selected_alarm, playbook)
                        save_audit(selected_alarm, action_result, f"单次审核触发: {playbook}")
                        st.success(f"✅ 动作已执行: {action_result['action']}")
                    else:
                        st.warning("无需防御指令。")
        st.markdown("---")

    with st.expander("查看原始所有告警数据 (Raw Logs)"):
        for idx, alarm in enumerate(alarms):
            title = f"{alarm['level']} - {alarm['event']}"
            if alarm["level"] == "高危": st.error(title)
            elif alarm["level"] == "中危": st.warning(title)
            else: st.info(title)

# ====================================================================
# 路由页面三：安全审计记录
# ====================================================================
elif menu == "三、安全审计记录":
    st.header("安全审计记录")
    
    audit_path = os.path.join("data", "audit.json")
    if os.path.exists(audit_path):
        with open(audit_path, "r", encoding="utf-8") as f:
            try: records = json.load(f)
            except json.JSONDecodeError: records = []

        if records:
            audit_df = pd.DataFrame(records)
            audit_df["time"] = pd.to_datetime(audit_df["time"])
            audit_df = audit_df.sort_values(by="time", ascending=False)
            audit_df["time"] = audit_df["time"].dt.strftime("%Y-%m-%d %H:%M:%S")

            status_options = ["全部"] + list(audit_df["result"].unique())
            selected_status = st.selectbox("按处理状态筛选:", status_options)
            
            if selected_status != "全部":
                audit_df = audit_df[audit_df["result"] == selected_status]

            display_df = audit_df[["time", "event_id", "event", "source_ip", "device", "action", "result"]]
            display_df.columns = ["操作时间", "事件编号", "告警事件", "来源IP", "联动设备", "执行动作", "处理结果"]

            st.dataframe(display_df, use_container_width=True, hide_index=True)
        else:
            st.info("当前审计文件为空，尚未产生自动化处理记录。")
    else:
        st.info("暂无安全审计记录。")