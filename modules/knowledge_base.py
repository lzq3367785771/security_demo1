import os
import time
import json
import chromadb
from chromadb.utils import embedding_functions

class DecisionKnowledgeBase:
    def __init__(self, db_path="data/chroma_db"):
        """
        初始化本地轻量级向量数据库
        """
        # 确保数据目录存在
        os.makedirs(db_path, exist_ok=True)
        
        # 创建持久化客户端，数据会保存在 db_path 目录下 (方便打包带走)
        self.client = chromadb.PersistentClient(path=db_path)
        
        # 使用默认的轻量级本地 Embedding 模型 (all-MiniLM-L6-v2)
        # 您也可以在这里替换为 OpenAI 或大厂的 Embedding API
        self.emb_fn = embedding_functions.DefaultEmbeddingFunction()
        
        # 获取或创建名为 'human_decisions' 的集合 (Collection)
        self.collection = self.client.get_or_create_collection(
            name="human_decisions",
            embedding_function=self.emb_fn
        )

    def add_decision(self, alarm, action, reason):
        """
        将人工的决策记录转化为向量并存入数据库
        """
        # 1. 构建用于生成向量的“核心上下文文本”
        features_str = json.dumps(alarm.get("features", {}))
        payload = alarm.get("raw_payload", "无报文")
        event = alarm.get("event", "未知告警")
        level = alarm.get("level", "未知等级")
        
        # 将环境信息、动作和人类的思考逻辑拼接成一段完整的话
        document_text = (
            f"告警事件: {level}-{event}。 "
            f"底层特征参数: {features_str}。 "
            f"原始报文内容: {payload}。 "
            f"专家处置动作: {action}。 "
            f"专家研判理由: {reason}"
        )
        
        # 2. 生成唯一 ID
        doc_id = f"record_{int(time.time() * 1000)}"
        
        # 3. 提取元数据 (方便后续进行结构化过滤或展示)
        metadata = {
            "event": event,
            "level": level,
            "action": action,
            "reason": reason,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # 4. 写入 ChromaDB
        self.collection.add(
            documents=[document_text],
            metadatas=[metadata],
            ids=[doc_id]
        )
        return doc_id

    def query_similar_cases(self, alarm, n_results=2):
        """
        当新告警发生时，检索最相似的历史人类决策
        """
        if self.collection.count() == 0:
            return []

        # 构造新告警的查询文本 (不包含动作和理由，只有现状)
        features_str = json.dumps(alarm.get("features", {}))
        payload = alarm.get("raw_payload", "无报文")
        event = alarm.get("event", "未知告警")
        level = alarm.get("level", "未知等级")
        
        query_text = (
            f"告警事件: {level}-{event}。 "
            f"底层特征参数: {features_str}。 "
            f"原始报文内容: {payload}。"
        )
        
        # 执行相似度检索
        results = self.collection.query(
            query_texts=[query_text],
            n_results=min(n_results, self.collection.count())
        )
        
        # 解析并返回检索到的元数据和距离
        similar_cases = []
        if results and results['metadatas'] and len(results['metadatas'][0]) > 0:
            for i in range(len(results['metadatas'][0])):
                case = results['metadatas'][0][i]
                # 距离越小，相似度越高
                distance = results['distances'][0][i] 
                case['similarity_distance'] = round(distance, 4)
                similar_cases.append(case)
                
        return similar_cases

# 实例化全局单例
kb_engine = DecisionKnowledgeBase()