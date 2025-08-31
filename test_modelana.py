from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import numpy as np

# 定义一个测试数据集
test_features = np.array([[1, 2, 3], [4, 5, 6], [7, 8, 9]])
# 创建一个标准化器和一个孤立森林分类器
scaler = StandardScaler()
clf = IsolationForest(contamination=0.1)
# 训练模型
train_features = scaler.fit_transform(test_features)
clf.fit(train_features)
def predict_anomaly(raw_features):
    #raw_features = train_features
    scaled = scaler.transform([raw_features])
    return clf.decision_function(scaled)[0]  # 负值表示异常程度
# 定义predict_anomaly的单元测试
def test_predict_anomaly():
    # 测试异常值
    anomaly_features = np.array([10, 20, 30])
    anomaly_score = predict_anomaly(anomaly_features)
    print('Anomaly score:', anomaly_score)
    assert anomaly_score < 0, "Anomaly score should be negative for anomalies"
    # 测试正常值
    normal_features = np.array([1, 2, 3])
    normal_score = predict_anomaly(normal_features)
    print('Normal score:', normal_score)
    assert normal_score >= 0, "Anomaly score should be positive for normal values"
    # 测试边界情况
    edge_features = np.array([1, 1, 1])
    edge_score = predict_anomaly(edge_features)
    print('Edge score:', edge_score)
    assert edge_score >= 0, "Anomaly score should be positive for edge cases"

if __name__ == '__main__':
    test_predict_anomaly()