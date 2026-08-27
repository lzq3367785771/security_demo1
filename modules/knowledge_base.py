import os
import time
import json
import chromadb
from chromadb.utils import embedding_functions

# ==========================================
# 核心修复：强制使用 HuggingFace 国内加速镜像站
# 解决本地大模型/向量模型下载的网络超时问题
# ==========================================
os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"

class DecisionKnowledgeBase:
    def __init__(self, db_path="data/chroma_db"):
        """
        初始化本地轻量级向量数据库
        """
        os.makedirs(db_path, exist_ok=True)
        self.client = chromadb.PersistentClient(path=db_path)
        
        # 核心修复：切换为 SentenceTransformer 引擎，它会自动走我们上面配置的 hf-mirror 镜像
        self.emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        
        self.collection = self.client.get_or_create_collection(
            name="human_decisions",
            embedding_function=self.emb_fn
        )


    def _infer_event_family(self, event_name):
        """
        将具体告警名称归类为稳定的安全事件家族。

        event_family 用于后续 RAG 的第一层结构化过滤，
        防止语义相似但安全含义不同的案例被错误混合。

        例如：
        - DDoS流量激增 / UDP Flood / SYN Flood -> ddos
        - 慢速隐蔽探测 / 端口扫描 / API探测 -> reconnaissance
        - 大促业务峰值 -> business_peak
        """

        event_name = str(
            event_name or ""
        ).strip()

        event_lower = event_name.lower()

        # ==================================================
        # 1. DDoS / Flood 类攻击
        # ==================================================
        if (
            "ddos" in event_lower
            or "flood" in event_lower
            or "流量洪泛" in event_name
            or "流量泛洪" in event_name
        ):
            return "ddos"

        # ==================================================
        # 2. 正常业务高峰
        # 必须和 DDoS 明确分开
        # ==================================================
        if (
            "大促" in event_name
            or "业务峰值" in event_name
            or "正常流量峰值" in event_name
        ):
            return "business_peak"

        # ==================================================
        # 3. SQL 注入
        # ==================================================
        if (
            "sql" in event_lower
            or "sql注入" in event_lower
            or "注入攻击" in event_name
        ):
            return "sql_injection"

        # ==================================================
        # 4. XSS
        # ==================================================
        if (
            "xss" in event_lower
            or "跨站脚本" in event_name
            or "跨站攻击" in event_name
        ):
            return "xss"

        # ==================================================
        # 5. 目录遍历 / LFI
        # ==================================================
        if (
            "目录遍历" in event_name
            or "路径遍历" in event_name
            or "lfi" in event_lower
        ):
            return "directory_traversal"

        # ==================================================
        # 6. 暴力破解 / 身份认证攻击
        # ==================================================
        if (
            "暴力破解" in event_name
            or "登录失败" in event_name
            or "口令破解" in event_name
            or "密码爆破" in event_name
            or "brute force" in event_lower
        ):
            return "brute_force"

        # ==================================================
        # 7. 侦察 / 扫描 / 探测
        #
        # 当前的“慢速隐蔽探测”将在这里归类。
        # ==================================================
        if (
            "慢速隐蔽探测" in event_name
            or "端口扫描" in event_name
            or "端口探测" in event_name
            or "服务扫描" in event_name
            or "服务探测" in event_name
            or "接口探测" in event_name
            or "api探测" in event_lower
            or "扫描行为" in event_name
            or "探测" in event_name
            or "侦察" in event_name
            or "recon" in event_lower
            or "probe" in event_lower
            or "scanning" in event_lower
        ):
            return "reconnaissance"

        # ==================================================
        # 8. 恶意软件
        # ==================================================
        if (
            "木马" in event_name
            or "病毒" in event_name
            or "恶意软件" in event_name
            or "malware" in event_lower
            or "trojan" in event_lower
        ):
            return "malware"

        # ==================================================
        # 9. 正常流量
        # ==================================================
        if (
            "正常流量" in event_name
            or "正常访问" in event_name
            or "合法流量" in event_name
        ):
            return "normal_traffic"

        # ==================================================
        # 10. 未知事件
        #
        # 绝不能统一返回 "unknown"。
        #
        # 否则：
        #   DNS异常
        #   可疑文件
        #   未知协议
        #
        # 会全部进入同一个家族，再次产生错误 RAG 匹配。
        # ==================================================
        return f"event::{event_name}"
    




    def add_decision(
        self,
        alarm,
        action,
        reason,
        ml_result=None,
        agent_decision=None,
        final_verdict="uncertain",
        review_status="approved",
        outcome_status="unknown"
    ):
        """
        将人工专家最终决策及其上下文转化为向量，
        并以结构化 metadata 的形式写入 ChromaDB。
        """

        # ==================================================
        # 1. 当前告警基本信息
        # ==================================================
        features = alarm.get("features", {})

        features_str = json.dumps(
            features,
            ensure_ascii=False,
            sort_keys=True
        )

        payload = alarm.get(
            "raw_payload",
            "无报文"
        )

        event = alarm.get(
            "event",
            "未知告警"
        )

        level = alarm.get(
            "level",
            "未知等级"
        )

        source_ip = str(
            alarm.get("source_ip", "")
        )

        # 已有的告警家族分类函数
        event_family = self._infer_event_family(
            event
        )

        # ==================================================
        # 2. 标准化 KNN / 规则结果
        # ==================================================
        ml_result = ml_result or {}

        knn_is_malicious = bool(
            ml_result.get(
                "is_malicious",
                False
            )
        )

        knn_confidence = float(
            ml_result.get(
                "confidence",
                0.0
            ) or 0.0
        )

        rule_hit = str(
            ml_result.get(
                "rule_hit"
            ) or ""
        )

        # ==================================================
        # 3. 标准化 Agent 决策结果
        # ==================================================
        agent_decision = agent_decision or {}

        agent_playbook = str(
            agent_decision.get(
                "playbook_name"
            ) or ""
        )

        agent_target_ip = str(
            agent_decision.get(
                "target_ip"
            ) or ""
        )

        # ==================================================
        # 4. 判断人工最终动作是否推翻 Agent 建议
        # ==================================================
        action_to_playbook = {
            "封禁攻击源 IP (Block IP)":
                "playbook_medium_risk",

            "标记为误报并放行 (False Positive / Allow)":
                "playbook_low_risk",

            "加入重点观察名单 (Watchlist)":
                "playbook_low_risk",

            "下发深度病毒查杀 (Deep Scan)":
                "playbook_high_risk"
        }

        human_expected_playbook = (
            action_to_playbook.get(
                action,
                ""
            )
        )

        human_overrode_agent = bool(
            agent_playbook
            and human_expected_playbook
            and agent_playbook
            != human_expected_playbook
        )

        # ==================================================
        # 5. 用于向量化检索的案例文本
        # ==================================================
        document_text = (
            f"告警事件: {level}-{event}。 "
            f"告警家族: {event_family}。 "
            f"底层特征参数: {features_str}。 "
            f"原始报文内容: {payload}。 "
            f"KNN判断: "
            f"{'异常/恶意' if knn_is_malicious else '正常'}。 "
            f"KNN置信度: {knn_confidence}%。 "
            f"规则命中: {rule_hit if rule_hit else '无'}。 "
            f"专家处置动作: {action}。 "
            f"专家研判理由: {reason}"
        )

        # ==================================================
        # 6. 生成案例唯一 ID
        # ==================================================
        doc_id = (
            f"record_{int(time.time() * 1000)}"
        )

        # ==================================================
        # 7. V2 结构化 metadata
        # ==================================================
        metadata = {
            # ----------------------------------------------
            # 告警基本信息
            # ----------------------------------------------
            "event": str(event),

            "event_family": str(
                event_family
            ),

            "level": str(level),

            "source_ip": source_ip,

            # Chroma metadata 不直接保存 dict，
            # 因此转成 JSON 字符串
            "features_json": features_str,

            # ----------------------------------------------
            # KNN / 规则判断
            # ----------------------------------------------
            "knn_is_malicious":
                knn_is_malicious,

            "knn_confidence":
                knn_confidence,

            "rule_hit":
                rule_hit,

            # ----------------------------------------------
            # Agent 辅助建议
            # ----------------------------------------------
            "agent_playbook":
                agent_playbook,

            "agent_target_ip":
                agent_target_ip,

            # ----------------------------------------------
            # 人工专家最终结果
            # ----------------------------------------------
            "verdict":
                str(final_verdict),

            "action":
                str(action),

            "reason":
                str(reason),

            "human_overrode_agent":
                human_overrode_agent,

            # ----------------------------------------------
            # 案例质量控制
            # ----------------------------------------------
            "review_status":
                str(review_status),

            "outcome_status":
                str(outcome_status),

            # ----------------------------------------------
            # 数据版本
            # ----------------------------------------------
            "schema_version": "2",

            "timestamp":
                time.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
        }

        # ==================================================
        # 8. 写入 ChromaDB
        # ==================================================
        self.collection.add(
            documents=[document_text],
            metadatas=[metadata],
            ids=[doc_id]
        )

        return doc_id


    def migrate_event_families(self):
        """
        一次性迁移现有 ChromaDB 人工专家案例的 event_family。

        迁移规则：
        1. 读取 collection 中全部案例。
        2. 根据 metadata["event"] 调用当前最新版
           _infer_event_family() 重新计算攻击家族。
        3. 如果旧 event_family 与新结果不同，则更新 metadata。
        4. 其他 metadata 字段全部原样保留。
        5. 不修改 documents，不重新生成 embedding。
        6. 可重复执行；已经正确的记录不会再次修改。
        """

        # ==================================================
        # 1. 读取现有知识库全部 metadata
        # ==================================================
        results = self.collection.get(
            include=[
                "metadatas"
            ]
        )

        record_ids = (
            results.get("ids")
            or []
        )

        metadatas = (
            results.get("metadatas")
            or []
        )

        # ==================================================
        # 2. 统计迁移结果
        # ==================================================
        total_count = len(record_ids)

        updated_count = 0
        unchanged_count = 0
        skipped_count = 0

        changes = []

        # ==================================================
        # 3. 逐条重新计算 event_family
        # ==================================================
        for index, case_id in enumerate(
            record_ids
        ):
            metadata = (
                metadatas[index]
                if index < len(metadatas)
                else None
            )

            # 极端情况下 metadata 缺失，
            # 不修改该案例
            if not metadata:
                skipped_count += 1
                continue

            # 使用副本，避免修改 Chroma 返回对象
            new_metadata = dict(
                metadata
            )

            event = str(
                new_metadata.get(
                    "event",
                    ""
                )
                or ""
            ).strip()

            # 没有 event 就无法安全分类
            if not event:
                skipped_count += 1
                continue

            old_family = str(
                new_metadata.get(
                    "event_family",
                    ""
                )
                or ""
            )

            # ==============================================
            # 核心：重新调用当前分类函数
            # ==============================================
            new_family = (
                self._infer_event_family(
                    event
                )
            )

            # 已经是正确结果，无需写数据库
            if old_family == new_family:
                unchanged_count += 1
                continue

            # ==============================================
            # 4. 只修改 event_family
            #
            # 其他：
            # event
            # level
            # KNN
            # Agent
            # action
            # reason
            # review_status
            # outcome_status
            #
            # 全部保留。
            # ==============================================
            new_metadata[
                "event_family"
            ] = new_family

            self.collection.update(
                ids=[
                    case_id
                ],
                metadatas=[
                    new_metadata
                ]
            )

            updated_count += 1

            changes.append({
                "case_id":
                    case_id,

                "event":
                    event,

                "old_event_family":
                    old_family
                    if old_family
                    else "<缺失>",

                "new_event_family":
                    new_family
            })

        # ==================================================
        # 5. 返回迁移报告
        # ==================================================
        return {
            "total_count":
                total_count,

            "updated_count":
                updated_count,

            "unchanged_count":
                unchanged_count,

            "skipped_count":
                skipped_count,

            "changes":
                changes
        }


    def migrate_quality_fields(self):
        """
        一次性补齐历史人工案例的质量控制字段。

        迁移规则：
        1. 缺少 review_status 的历史案例：
           默认设置为 approved。

           原因：
           这些旧记录本身就是通过“人工最终决策”
           表单产生的，为了保持现有 Demo 的学习行为，
           暂时视为已经人工确认。

        2. 缺少 outcome_status 的历史案例：
           设置为 unknown。

           因为这些历史案例虽然有人工作出最终决策，
           但尚未记录实际处置效果，
           所以不能直接认为 effective。

        3. 已经存在合法字段的 V2 案例保持不变。

        4. 不修改：
           event
           event_family
           KNN
           Agent
           verdict
           action
           reason
           document
           embedding
        """

        # ==================================================
        # 1. 读取全部案例 metadata
        # ==================================================
        results = self.collection.get(
            include=[
                "metadatas"
            ]
        )

        record_ids = (
            results.get("ids")
            or []
        )

        metadatas = (
            results.get("metadatas")
            or []
        )

        # ==================================================
        # 2. 合法状态定义
        # ==================================================
        valid_review_statuses = {
            "pending",
            "approved",
            "rejected"
        }

        valid_outcome_statuses = {
            "unknown",
            "effective",
            "ineffective"
        }

        total_count = len(
            record_ids
        )

        updated_count = 0
        unchanged_count = 0
        skipped_count = 0

        changes = []
        invalid_cases = []

        # ==================================================
        # 3. 遍历所有历史案例
        # ==================================================
        for index, case_id in enumerate(
            record_ids
        ):
            metadata = (
                metadatas[index]
                if index < len(metadatas)
                else None
            )

            if not metadata:
                skipped_count += 1
                continue

            new_metadata = dict(
                metadata
            )

            changed_fields = {}

            # ==================================================
            # 4. 补齐 review_status
            # ==================================================
            review_status = (
                new_metadata.get(
                    "review_status"
                )
            )

            if not review_status:
                new_metadata[
                    "review_status"
                ] = "approved"

                changed_fields[
                    "review_status"
                ] = {
                    "old": "<缺失>",
                    "new": "approved"
                }

            elif (
                review_status
                not in valid_review_statuses
            ):
                # 出现未知值时不要擅自覆盖
                invalid_cases.append({
                    "case_id":
                        case_id,

                    "field":
                        "review_status",

                    "value":
                        review_status
                })

            # ==================================================
            # 5. 补齐 outcome_status
            # ==================================================
            outcome_status = (
                new_metadata.get(
                    "outcome_status"
                )
            )

            if not outcome_status:
                new_metadata[
                    "outcome_status"
                ] = "unknown"

                changed_fields[
                    "outcome_status"
                ] = {
                    "old": "<缺失>",
                    "new": "unknown"
                }

            elif (
                outcome_status
                not in valid_outcome_statuses
            ):
                # 同样不自动覆盖异常数据
                invalid_cases.append({
                    "case_id":
                        case_id,

                    "field":
                        "outcome_status",

                    "value":
                        outcome_status
                })

            # ==================================================
            # 6. 没有变化则跳过数据库写操作
            # ==================================================
            if not changed_fields:
                unchanged_count += 1
                continue

            # ==================================================
            # 7. 只更新 metadata
            # ==================================================
            self.collection.update(
                ids=[
                    case_id
                ],

                metadatas=[
                    new_metadata
                ]
            )

            updated_count += 1

            changes.append({
                "case_id":
                    case_id,

                "event":
                    new_metadata.get(
                        "event",
                        "未知告警"
                    ),

                "changed_fields":
                    changed_fields
            })

        # ==================================================
        # 8. 返回迁移报告
        # ==================================================
        return {
            "total_count":
                total_count,

            "updated_count":
                updated_count,

            "unchanged_count":
                unchanged_count,

            "skipped_count":
                skipped_count,

            "invalid_count":
                len(invalid_cases),

            "changes":
                changes,

            "invalid_cases":
                invalid_cases
        }



    def query_similar_cases(
        self,
        alarm,
        n_results=5,
        max_distance=0.35
    ):
        """
        检索与当前告警属于相同攻击家族的历史人工案例。

        安全原则：
        1. 先使用 event_family 进行确定性过滤。
        2. 不同攻击家族的案例禁止进入候选集。
        3. 同攻击家族并不意味着结论相同，仍需进行向量距离过滤。
        4. 超过距离阈值的案例不提供给 Agent。
        5. 对重复人工经验进行去重。
        6. 找不到同家族案例时返回空列表，不回退到全库检索。
        """
        record_count = self.collection.count()

        if record_count == 0:
            return []

        features_str = json.dumps(
            alarm.get("features", {}),
            ensure_ascii=False,
            sort_keys=True
        )

        payload = alarm.get(
            "raw_payload",
            "无报文"
        )

        event = alarm.get(
            "event",
            "未知告警"
        )

        level = alarm.get(
            "level",
            "未知等级"
        )

        # ==================================================
        # 1. 将当前具体告警映射为稳定的攻击家族
        # ==================================================
        event_family = self._infer_event_family(
            event
        )

        # ==================================================
        # 2. 构建向量检索文本
        # ==================================================
        query_text = (
            f"告警事件: {level}-{event}。 "
            f"告警家族: {event_family}。 "
            f"底层特征参数: {features_str}。 "
            f"原始报文内容: {payload}。"
        )

        # 多召回一些同家族候选，
        # 再通过向量距离和重复内容进行二次筛选
        candidate_count = min(
            max(
                n_results * 5,
                20
            ),
            record_count
        )

        # ==================================================
        # 3. 第一层：metadata 攻击家族过滤
        # ==================================================
        results = self.collection.query(
            query_texts=[
                query_text
            ],

            n_results=
                candidate_count,

            where={
                "$and": [
                    {
                        "event_family": {
                            "$eq":
                                event_family
                        }
                    },

                    {
                        "review_status": {
                            "$eq":
                                "approved"
                        }
                    },

                    {
                        "outcome_status": {
                            "$in": [
                                "unknown",
                                "effective"
                            ]
                        }
                    }
                ]
            },

            include=[
                "metadatas",
                "documents",
                "distances"
            ]
        )

        result_ids = (
            results.get("ids")
            or [[]]
        )[0]

        result_metadatas = (
            results.get(
                "metadatas"
            )
            or [[]]
        )[0]

        result_documents = (
            results.get(
                "documents"
            )
            or [[]]
        )[0]

        result_distances = (
            results.get(
                "distances"
            )
            or [[]]
        )[0]

        similar_cases = []
        seen_cases = set()

        # ==================================================
        # 4. 第二层：程序级攻击家族校验
        # ==================================================
        for index, metadata in enumerate(
            result_metadatas
        ):
            case = dict(
                metadata or {}
            )

            # 即便数据库过滤发生异常，
            # 不同攻击家族仍禁止进入 Agent
            # ==================================================
            # 第二层确定性质量校验
            #
            # 即使 Chroma metadata where 被误改，
            # 不合格案例仍禁止进入 Agent。
            # ==================================================

            # 1. 攻击家族必须一致
            # ==================================================
            # 第二层确定性质量校验
            #
            # 即使 Chroma metadata where 被误改，
            # 不合格案例仍禁止进入 Agent。
            # ==================================================

            # 1. 攻击家族必须一致
            if (
                case.get(
                    "event_family"
                )
                != event_family
            ):
                continue

            # 2. 必须经过人工审核批准
            if (
                case.get(
                    "review_status"
                )
                != "approved"
            ):
                continue

            # 3. 已确认处置无效的案例禁止学习
            if (
                case.get(
                    "outcome_status"
                )
                not in {
                    "unknown",
                    "effective"
                }
            ):
                continue

            # 2. 必须经过人工审核批准
            if (
                case.get(
                    "review_status"
                )
                != "approved"
            ):
                continue

            # 3. 已确认处置无效的案例禁止学习
            if (
                case.get(
                    "outcome_status"
                )
                not in {
                    "unknown",
                    "effective"
                }
            ):
                continue

            distance = (
                result_distances[index]
                if index
                < len(
                    result_distances
                )
                else None
            )

            if distance is None:
                continue

            distance = float(
                distance
            )

            # ==================================================
            # 5. 向量距离门槛
            # ==================================================
            if (
                distance
                > max_distance
            ):
                continue

            # ==================================================
            # 6. 重复案例去重
            # ==================================================
            normalized_reason = " ".join(
                str(
                    case.get(
                        "reason",
                        ""
                    )
                ).split()
            )

            duplicate_key = (
                case.get(
                    "event_family",
                    ""
                ),

                case.get(
                    "action",
                    ""
                ),

                normalized_reason
            )

            if (
                duplicate_key
                in seen_cases
            ):
                continue

            seen_cases.add(
                duplicate_key
            )

            # ==================================================
            # 7. 补充案例检索信息
            # ==================================================
            case["case_id"] = (
                result_ids[index]
                if index
                < len(result_ids)
                else
                f"unknown_case_{index}"
            )

            case["document"] = (
                result_documents[index]
                if index
                < len(
                    result_documents
                )
                else ""
            )

            case[
                "similarity_distance"
            ] = round(
                distance,
                4
            )

            similar_cases.append(
                case
            )

            if (
                len(similar_cases)
                >= n_results
            ):
                break

        return similar_cases

# 实例化全局单例
kb_engine = DecisionKnowledgeBase()