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
from modules.action import execute_action, execute_human_decision
from modules.audit import save_audit
from modules.ml_engine import ml_engine
from modules.knowledge_base import kb_engine

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
                ml_res_dict = {
                    "is_malicious": is_malicious,
                    "confidence": confidence,
                    "rule_hit": rule_name
                }

                event_family = (
                    kb_engine._infer_event_family(
                        alarm.get(
                            "event",
                            "未知告警"
                        )
                    )
                )

                similar_cases = (
                    kb_engine.query_similar_cases(
                        alarm,
                        n_results=5
                    )
                )

                analysis_text, agent_decision = analyze_event(
                    alarm,
                    ml_result=ml_res_dict,
                    similar_cases=similar_cases,
                    event_family=event_family
                )

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
                status_text.text(
                    f"🧠 Agent 正在处理："
                    f"{alarm.get('level', '')}-"
                    f"{alarm.get('event', '')}..."
                )

                is_malicious, conf = ml_engine.predict_traffic(
                    alarm.get("features", {})
                )

                ml_res_dict = {
                    "is_malicious": is_malicious,
                    "confidence": round(
                        conf * 100
                        if is_malicious
                        else (1 - conf) * 100,
                        1
                    ),
                    "rule_hit": alarm.get("rule_hit")
                }

                event_family = (
                    kb_engine._infer_event_family(
                        alarm.get(
                            "event",
                            "未知告警"
                        )
                    )
                )

                similar_cases = (
                    kb_engine.query_similar_cases(
                        alarm,
                        n_results=5
                    )
                )

                _, agent_decision = analyze_event(
                    alarm,
                    ml_result=ml_res_dict,
                    similar_cases=similar_cases,
                    event_family=event_family
                )
                
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
                
                # ==================================================
                # 第一阶段：KNN 机器学习初判
                # ==================================================
                st.markdown("##### ① KNN 机器学习初判")

                features = selected_alarm.get("features", {})
                if features:
                    f1, f2, f3 = st.columns(3)
                    f1.metric("连接频率", features.get("conn_freq", 0))
                    f2.metric("包大小", features.get("packet_size", 0))
                    f3.metric("错误率", features.get("error_rate", 0))

                    is_mal, conf = ml_engine.predict_traffic(features)
                else:
                    is_mal, conf = False, 0.0
                    st.warning("当前告警没有可供 KNN 分析的特征数据。")

                knn_confidence = round(
                    conf * 100 if is_mal else (1 - conf) * 100,
                    1
                )

                if is_mal:
                    st.error(
                        f"机器初判结果：异常/恶意流量 "
                        f"(置信度 {knn_confidence:.1f}%)"
                    )
                else:
                    st.success(
                        f"机器初判结果：正常流量 "
                        f"(置信度 {knn_confidence:.1f}%)"
                    )

                if "raw_payload" in selected_alarm:
                    st.code(selected_alarm["raw_payload"])

                # 为每条告警建立独立的页面状态
                alarm_identity = "|".join([
                    str(selected_alarm.get("time", "")),
                    str(selected_alarm.get("source_ip", "")),
                    str(selected_alarm.get("event", ""))
                ])

                agent_result_key = f"agent_review::{alarm_identity}"
                expert_action_key = f"expert_action::{alarm_identity}"

                expert_actions = [
                    "封禁攻击源 IP (Block IP)",
                    "标记为误报并放行 (False Positive / Allow)",
                    "下发深度病毒查杀 (Deep Scan)",
                    "加入重点观察名单 (Watchlist)"
                ]

                if expert_action_key not in st.session_state:
                    st.session_state[expert_action_key] = expert_actions[0]

                st.divider()

                # ==================================================
                # 第二阶段：Agent 辅助决策
                # ==================================================
                st.markdown("##### ② Agent 辅助研判")
                st.info(
                    "Agent 只提供分析和处置建议，不会在此阶段执行任何动作。"
                    "最终决策必须由人工专家确认。"
                )

                if st.button(
                    "🤖 请求 Agent 进行辅助决策",
                    key=f"agent_button::{alarm_identity}",
                    type="secondary",
                    use_container_width=True
                ):
                    ml_result = {
                        "is_malicious": is_mal,
                        "confidence": knn_confidence,
                        "rule_hit": rule_hit
                    }

                    try:
                        with st.spinner(
                            "Agent 正在检索人工经验并进行融合研判..."
                        ):
                            # 1. 获取当前告警所属攻击家族
                            event_family = (
                                kb_engine._infer_event_family(
                                    selected_alarm.get(
                                        "event",
                                        "未知告警"
                                    )
                                )
                            )

                            # 2. 从 ChromaDB 检索同攻击家族案例
                            similar_cases = (
                                kb_engine.query_similar_cases(
                                    selected_alarm,
                                    n_results=5
                                )
                            )

                            # 3. 将 KNN、RAG 案例和攻击家族交给 Agent
                            analysis_text, agent_decision = analyze_event(
                                selected_alarm,
                                ml_result=ml_result,
                                similar_cases=similar_cases,
                                event_family=event_family
                            )

                        # 4. 将分析结果和检索案例保存在页面状态中
                        st.session_state[agent_result_key] = {
                            "analysis": analysis_text,
                            "decision": agent_decision,
                            "similar_cases": similar_cases
                        }

                        # 将 Agent 建议转换为人工表单中的候选动作
                        playbook_action_map = {
                            "playbook_low_risk":
                                "加入重点观察名单 (Watchlist)",
                            "playbook_medium_risk":
                                "封禁攻击源 IP (Block IP)",
                            "playbook_high_risk":
                                "封禁攻击源 IP (Block IP)"
                        }

                        if agent_decision:
                            suggested_action = playbook_action_map.get(
                                agent_decision.get("playbook_name")
                            )
                            if suggested_action:
                                st.session_state[expert_action_key] = suggested_action

                    except Exception as exc:
                        st.session_state.pop(agent_result_key, None)
                        st.error(f"Agent 辅助研判失败：{exc}")

                agent_result = st.session_state.get(agent_result_key)




                if agent_result:
                    retrieved_cases = agent_result.get(
                        "similar_cases",
                        []
                    )

                    if retrieved_cases:
                        st.success(
                            f"📚 已检索到 "
                            f"{len(retrieved_cases)} 条"
                            f"同攻击家族且通过距离门槛的人工案例"
                        )

                        with st.expander(
                            "查看本次 Agent 使用的"
                            "同攻击家族人工案例"
                        ):
                            for case_index, case in enumerate(
                                retrieved_cases,
                                start=1
                            ):
                                st.markdown(
                                    f"""
**案例 {case_index}：{case.get("case_id", "未知")}**

- 历史告警：{case.get("level", "未知")} - {case.get("event", "未知")}
- 攻击家族：{case.get("event_family", "未知")}
- 人工最终动作：{case.get("action", "未知")}
- 人工决策理由：{case.get("reason", "未记录")}
- 相似距离：{case.get("similarity_distance", "未知")}
- 决策时间：{case.get("timestamp", "未知")}
"""
                                )

                                st.divider()

                    else:
                        st.warning(
                            "📚 当前知识库没有符合条件的"
                            "同攻击家族历史案例。"
                            "Agent 不得使用其他攻击家族的经验"
                            "覆盖本次 KNN 判断。"
                        )

                    st.markdown("###### Agent 分析报告")

                    st.markdown(agent_result.get("analysis", "未生成分析报告"))

                    agent_decision = agent_result.get("decision")

                    if agent_decision:
                        playbook_labels = {
                            "playbook_low_risk": "低风险观察",
                            "playbook_medium_risk": "中风险封禁",
                            "playbook_high_risk": "高风险隔离"
                        }

                        playbook_name = agent_decision.get("playbook_name")
                        target_ip = agent_decision.get(
                            "target_ip",
                            selected_alarm.get("source_ip", "")
                        )

                        st.warning(
                            f"Agent 建议："
                            f"【{playbook_labels.get(playbook_name, playbook_name)}】；"
                            f"目标 IP：{target_ip}"
                        )
                    else:
                        st.warning("Agent 已完成分析，但没有生成明确的处置建议。")

                    st.caption(
                        "以上内容仅供专家参考，尚未执行任何封禁、隔离或放行动作。"
                    )

                st.divider()

                # ==================================================
                # 第三阶段：人工专家最终决策
                # ==================================================
                st.markdown("##### ③ 专家最终决策 (Human-in-the-Loop)")
                st.info(
                    "Agent 建议会预填到处置动作中，但专家可以修改。"
                    "只有提交本表单后才会执行最终动作并写入知识库。💡 在此提交的处置动作与理由，将被向量化存入知识库。Agent 将在未来的自动化研判中学习并复用这些人类经验。"
                )

                
                # 使用 st.form 避免在输入文字时触发页面频繁刷新
                with st.form(key="expert_decision_form"):
                    decision_action = st.selectbox(
                        "1. 请选择最终处置动作：",
                        expert_actions,
                        key=expert_action_key,
                        help="Agent 建议仅作为默认选项，专家可以自由修改。"
                    )
                    
                    decision_reason = st.text_area(
                        "2. 请填写研判理由 (Agent 学习的核心依据)：", 
                        placeholder="例如：虽然流量较大，但属于大促期间正常比例，且无恶意 Payload，判定为误报。请放心放行。"
                    )
                    
                    col_submit, col_close = st.columns([3, 1])
                    with col_submit:
                        submit_decision = st.form_submit_button(
                            "✅ 确认并执行人工最终决策",
                            type="primary"
                        )
                    with col_close:
                        close_btn = st.form_submit_button("✖️ 关闭详情")

                # 表单提交后的处理逻辑
                if submit_decision:
                    if not decision_reason.strip():
                        st.error(
                            "⚠️ 请务必填写研判理由！"
                            "这是 Agent 未来推理的重要上下文。"
                        )

                    else:
                        with st.spinner(
                            "📦 正在向量化专家经验并写入数据库..."
                        ):

                            # ==========================================
                            # 1. 获取本次 Agent 辅助研判结果
                            # ==========================================
                            agent_reference = (
                                st.session_state.get(
                                    agent_result_key
                                )
                            )

                            agent_decision_for_kb = {}

                            if agent_reference:
                                agent_decision_for_kb = (
                                    agent_reference.get(
                                        "decision"
                                    )
                                    or {}
                                )

                            # ==========================================
                            # 2. 构造本次 KNN / 规则结果
                            # ==========================================
                            ml_result_for_kb = {
                                "is_malicious":
                                    is_mal,

                                "confidence":
                                    knn_confidence,

                                "rule_hit":
                                    rule_hit
                            }

                            # ==========================================
                            # 3. 写入 V2 ChromaDB 专家知识库
                            # ==========================================
                            doc_id = kb_engine.add_decision(
                                alarm=selected_alarm,

                                action=decision_action,

                                reason=decision_reason,

                                ml_result=
                                    ml_result_for_kb,

                                agent_decision=
                                    agent_decision_for_kb,

                                # 当前界面尚未增加
                                # “人工最终风险判断”控件，
                                # 所以暂时标为 uncertain
                                final_verdict=
                                    "uncertain",

                                # 当前是人工主动提交，
                                # Step 1 暂时认为已经审核
                                review_status=
                                    "approved",

                                # 实际处置效果暂未反馈
                                outcome_status=
                                    "unknown"
                            )

                            # ==========================================
                            # 4. 执行人工最终指定的防御动作
                            # ==========================================
                            action_result = (
                                execute_human_decision(
                                    selected_alarm,
                                    decision_action
                                )
                            )

                            # ==========================================
                            # 5. 获取 Agent 分析文本用于审计
                            # ==========================================
                            agent_reference_text = (
                                agent_reference.get(
                                    "analysis",
                                    ""
                                )
                                if agent_reference
                                else
                                "本次未调用 Agent 辅助研判"
                            )

                            # ==========================================
                            # 6. 保存审计记录
                            # ==========================================
                            save_audit(
                                selected_alarm,
                                action_result,
                                (
                                    f"人工最终决策: "
                                    f"{decision_action}\n"
                                    f"Agent参考意见: "
                                    f"{agent_reference_text}"
                                )
                            )

                        st.success(
                            f"✅ 专家经验已成功沉淀至知识库！"
                            f"(记录 ID: {doc_id})"
                        )

                        st.balloons()

                if close_btn:
                    st.session_state.view_detail_alarm = None
                    st.rerun()
                    
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