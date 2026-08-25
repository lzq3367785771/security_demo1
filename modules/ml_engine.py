import numpy as np
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler

class MLDefenseEngine:
    def __init__(self):
        """
        初始化机器学习防御引擎
        """
        # 使用 distance 权重可以更好地处理特征空间中分布不均的样本点
        self.knn = KNeighborsClassifier(n_neighbors=5, weights='distance', p=2)
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # 系统启动时自动拟合基线模型
        self._train_baseline_model()

    def _train_baseline_model(self):
        """
        在内存中快速拟合一个基线模型。
        在真实的生产环境中，这里应替换为连接数据库拉取历史流量进行 fit。
        """
        # 1. 构造正常流量样本 (标签 0)
        # 特征顺序: [conn_freq, packet_size, error_rate]
        normal_data = np.array([
            [20, 500, 0.01], [35, 800, 0.05], [15, 400, 0.02],
            [50, 1200, 0.03], [25, 600, 0.01], [40, 900, 0.04],
            [10, 300, 0.00], [60, 1500, 0.02], [30, 700, 0.01],
            [45, 1000, 0.03]
        ])
        normal_labels = np.zeros(len(normal_data))

        # 2. 构造我们在 mock_stream 中定义的各类攻击流量样本 (标签 1)
        attack_data = np.array([
            [1500, 50, 0.85],  # 端口扫描
            [8000, 500, 0.60], # DDoS
            [20, 2000, 0.10],  # SQL注入
            [30, 1800, 0.15],  # XSS
            [15, 200, 0.90],   # 爆破异常登录
            [1200, 60, 0.80],  # 端口扫描变种
            [10000, 100, 0.70] # DDoS变种
        ])
        attack_labels = np.ones(len(attack_data))

        # 3. 合并数据集
        X_train = np.vstack((normal_data, attack_data))
        y_train = np.concatenate((normal_labels, attack_labels))

        # 4. 特征标准化 (消除量纲差异，保证 KNN 距离度量的统计学意义)
        X_train_scaled = self.scaler.fit_transform(X_train)

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

        # 必须使用与训练集相同的 scaler 进行转换
        x_new_scaled = self.scaler.transform(x_new)

        # 预测类别与概率
        prediction = self.knn.predict(x_new_scaled)[0]
        probabilities = self.knn.predict_proba(x_new_scaled)[0]
        
        is_malicious = bool(prediction == 1)
        # 获取判定为恶意的置信度概率
        malicious_prob = probabilities[1] 

        return is_malicious, malicious_prob

# 实例化一个全局单例，供其他模块导入使用
ml_engine = MLDefenseEngine()