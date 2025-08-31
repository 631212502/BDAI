from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np

# 加载训练数据(样例)
test_packet_series = {
    'timestamp': np.array([1, 2, 3, 4, 5]),
    'stNum': np.array([1, 2, 3, 4, 5]),
    'sqNum': np.array([1, 2, 3, 4, 5]),
    'payload_length': np.array([100, 200, 300, 400, 500]),
    'datSet': np.array([1, 2, 3, 4, 5]),
    'timeToLive': np.array([1, 2, 3, 4, 5]),
    'dstMac': np.array(['01-0C-CD-01-00-00', '01-0C-CD-01-00-00', '01-0C-CD-01-00-00', '01-0C-CD-01-00-00', '01-0C-CD-01-00-00'])
}
# 定义期望的特征
expected_features = {
    'interval_mean': 1.0,
    'interval_std': 0.0,
    'st_num_changes': 5,
    'sq_num_jumps': 0,
    'payload_size_var': 2500.0,
    'datSet_changes': 5,
    'ttl_violations': 0,
    'mac_errors': 0
}

# 数据预处理
def extract_features(packet_series):
    """从GOOSE报文序列提取特征"""
    features = {
        # 时间特征
        'interval_mean': np.mean(np.diff(packet_series['timestamp'])),
        'interval_std': np.std(np.diff(packet_series['timestamp'])),
        
        # 序列号特征
        'st_num_changes': len(set(packet_series['stNum'])),
        'sq_num_jumps': sum(np.diff(packet_series['sqNum']) != 1),
        
        # 内容特征
        'payload_size_var': np.var(packet_series['payload_length']),
        'datSet_changes': len(set(packet_series['datSet'])),
        
        # 网络特征
        'ttl_violations': sum(packet_series['timeToLive'] < 2),
        'mac_errors': sum(packet_series['dstMac'] != '01-0C-CD-01-00-00')
    }
    return features


train_features = extract_features(test_packet_series) #单测
# 特征标准化
scaler = StandardScaler()
X_train = scaler.fit_transform(train_features)

# 模型训练
clf = IsolationForest(
    n_estimators=100,
    max_samples='auto',
    contamination=0.01,  # 预期异常比例
    random_state=42
)
clf.fit(X_train)



# 异常预测
def predict_anomaly(raw_features):
    #raw_features = train_features
    scaled = scaler.transform([raw_features])
    return clf.decision_function(scaled)[0]  # 负值表示异常程度

if __name__ == '__main__':
    #print(train_features)
    #train_features = [extract_features(packet_series) for packet_series in train_data] # 训练数据
   
    anomaly_score = predict_anomaly(train_features)
    print('Anomaly score:', anomaly_score)