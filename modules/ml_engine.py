import numpy as np
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler

class MLDefenseEngine:
    def __init__(self):
        """
        初始化机器学习防御引擎
        """
        self.scaler = StandardScaler()
        self.is_trained = False
        self.knn = None 
        
        # 系统启动时自动拟合基线模型
        self._train_baseline_model()

    def _train_baseline_model(self):
        """
        在内存中快速拟合一个基线模型。
        """
        # ==========================================
        # 1. 构造正常流量样本 (标签 0)
        # 扩充大促业务峰值密度，确保 K=5 邻域内有充足的安全样本支持
        # ==========================================
        normal_data = np.array([
            # 基础业务基线
            [20, 500, 0.01], [35, 800, 0.05], [15, 400, 0.02],
            [50, 1200, 0.03], [25, 600, 0.01], [40, 900, 0.04],
            [10, 300, 0.00], [60, 1500, 0.02], [30, 700, 0.01],
            [45, 1000, 0.03],
            
            # 高密度大促业务峰值簇 (频率与包大小保持正常协方差正比例)
            [65, 1625, 0.01], [68, 1700, 0.02], [70, 1750, 0.02],
            [72, 1800, 0.03], [75, 1875, 0.01], [78, 1950, 0.02],
            [80, 2000, 0.01], [82, 2050, 0.03], [85, 2125, 0.02],
            [88, 2200, 0.04]
        ])
        normal_labels = np.zeros(len(normal_data))

        # ==========================================
        # 2. 构造各类攻击流量样本 (标签 1)
        # ==========================================
        attack_data = np.array([
            [1500, 50, 0.85],  # 端口扫描
            [8000, 500, 0.60], # DDoS
            [20, 2000, 0.10],  # SQL注入
            [30, 1800, 0.15],  # XSS
            [15, 200, 0.90],   # 爆破异常登录
            [1200, 60, 0.80],  # 端口扫描变种
            [10000, 100, 0.70],# DDoS变种
            [18, 1450, 0.02],  # 慢速隐蔽探测 (低频超大包，违背协方差结构)
            [20, 1500, 0.04]
        ])
        attack_labels = np.ones(len(attack_data))

        # 3. 合并数据集并进行标准化
        X_train = np.vstack((normal_data, attack_data))
        y_train = np.concatenate((normal_labels, attack_labels))
        X_train_scaled = self.scaler.fit_transform(X_train)

        # ==========================================
        # 4. 协方差矩阵纯净化计算 (基于正常流量)
        # ==========================================
        normal_scaled = X_train_scaled[y_train == 0]
        cov_matrix = np.cov(normal_scaled, rowvar=False)
        inv_cov_matrix = np.linalg.pinv(cov_matrix)

        # 实例化 KNN，指定马氏距离与逆协方差矩阵
# ==========================================
        # 优化：引入 Ball Tree 空间索引机制
        # ==========================================
        self.knn = KNeighborsClassifier(
            n_neighbors=5, 
            algorithm='ball_tree',  # 核心修改：强制指定使用球树构建索引
            leaf_size=30,           # 性能参数：叶子节点样本数，平衡建树与查询时间的阈值
            weights='distance', 
            metric='mahalanobis', 
            metric_params={'VI': inv_cov_matrix}
        )

        # 5. 拟合模型
        self.knn.fit(X_train_scaled, y_train)
        self.is_trained = True

    def predict_traffic(self, features_dict):
        """
        对输入的单条流量特征进行二分类预测
        """
        if not self.is_trained:
            return False, 0.0

        # 提取特征并保持与训练集一致的顺序
        x_new = np.array([[
            features_dict.get("conn_freq", 0),
            features_dict.get("packet_size", 0),
            features_dict.get("error_rate", 0.0)
        ]])

        # 使用与训练集相同的 scaler 进行转换
        x_new_scaled = self.scaler.transform(x_new)

        # 预测类别与概率
        prediction = self.knn.predict(x_new_scaled)[0]
        probabilities = self.knn.predict_proba(x_new_scaled)[0]
        
        is_malicious = bool(prediction == 1)
        malicious_prob = probabilities[1] 

        return is_malicious, malicious_prob

# 实例化全局单例
ml_engine = MLDefenseEngine()