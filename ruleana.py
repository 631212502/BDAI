import pyshark
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import matplotlib.pyplot as plt

class GooseAnomalyDetector:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        cap = pyshark.FileCapture(
        pcap_file,
        display_filter='goose'  # 只过滤GOOSE报文
    )
        # self.packets = rdpcap(pcap_file)
        self.packets = cap
        self.goose_data = []
        self.anomalies = []
    
    def parse_goose_packets(self):
        """解析GOOSE报文"""     
        for packet in self.packets:
            try:
                if hasattr(packet, 'goose'):
                    goose_info = {
                        'frame_number': packet.number,
                        'timestamp': packet.sniff_time,
                        'src_mac': packet.eth.src,
                        'dst_mac': packet.eth.dst,
                        'appid': getattr(packet.goose, 'appid', 'N/A'),
                        'gocb_ref': getattr(packet.goose, 'gocbref', 'N/A'),
                        'time_allowed': getattr(packet.goose, 'timeallowedtolive', 'N/A'),
                        'st_num': getattr(packet.goose, 'stnum', 'N/A'),
                        'sq_num': getattr(packet.goose, 'sqnum', 'N/A'),
                        'test': getattr(packet.goose, 'test', 'N/A'),
                        'conf_rev': getattr(packet.goose, 'confrev', 'N/A'),
                        'nds_com': getattr(packet.goose, 'ndsCom', False),
                        'packet_size': len(packet)
                    }
                    self.goose_data.append(goose_info)
            except AttributeError as e:
                print(f"解析错误: {e}")
                continue
        
        self.df = pd.DataFrame(self.goose_data)
        if not self.df.empty:
            self.df = self.df.sort_values('timestamp')
            self.df['time_diff'] = self.df['timestamp'].diff().dt.total_seconds()
    
    def detect_anomalies(self):
        """检测所有类型的异常"""
        if self.df.empty:
            return []
        
        self.anomalies = []
        
        # 检测各种异常
        self._detect_sequence_anomalies()
        self._detect_timing_anomalies()
        self._detect_stnum_anomalies()
        self._detect_test_mode_anomalies()
        self._detect_config_anomalies()
        self._detect_communication_anomalies()
        self._detect_rate_anomalies()
        
        return self.anomalies
    
    def _detect_sequence_anomalies(self):
        """检测序列号异常"""
        for gocb_ref, group in self.df.groupby('gocb_ref'):
            # 将字符串类型的序列号转换为整数
            sq_nums = [int(sq) if sq != 'N/A' and sq.isdigit() else 0 for sq in group['sq_num'].values]
            #print("sq_nums: ", sq_nums)
            # 检查序列号连续性
            for i in range(1, len(sq_nums)):
                expected_sq = (sq_nums[i-1] + 1)  # GOOSE序列号是16位循环
                if sq_nums[i] != expected_sq and sq_nums[i] != 0:  # 允许从0重新开始
                    self.anomalies.append({
                        'type': 'SEQUENCE_GAP',
                        'timestamp': group.iloc[i]['timestamp'],
                        'gocb_ref': gocb_ref,
                        'severity': 'HIGH',
                        'message': f'序列号不连续: {sq_nums[i-1]} -> {sq_nums[i]} (期望: {expected_sq})'
                    })
    
    def _detect_timing_anomalies(self):
        """检测时间间隔异常"""
        for gocb_ref, group in self.df.groupby('gocb_ref'):
            time_diffs = group['time_diff'].dropna().values
            # 将字符串类型的time_allowed转换为浮点数，如果是'N/A'则使用默认值
            time_allowed_str = group['time_allowed'].iloc[0]
            if time_allowed_str != 'N/A' and time_allowed_str.replace('.', '', 1).isdigit():
                time_allowed = float(time_allowed_str) / 1000.0  # 转换为秒
            else:
                time_allowed = 1.0  # 默认1秒
            
            if len(time_diffs) > 1:
                avg_interval = np.mean(time_diffs[1:])  # 忽略第一个NaN
                
                # 检查是否超过允许生存时间
                for i, diff in enumerate(time_diffs[1:], 1):
                    if diff > time_allowed * 2:  # 允许2倍容忍度
                        self.anomalies.append({
                            'type': 'TIMEOUT',
                            'timestamp': group.iloc[i]['timestamp'],
                            'gocb_ref': gocb_ref,
                            'severity': 'CRITICAL',
                            'message': f'报文超时: {diff:.3f}s > 允许时间 {time_allowed:.3f}s'
                        })
                
                # 检查间隔时间异常波动
                if len(time_diffs) > 3:
                    std_dev = np.std(time_diffs[1:])
                    if std_dev > avg_interval * 0.5:  # 标准差超过平均值的50%
                        self.anomalies.append({
                            'type': 'INTERVAL_VARIATION',
                            'timestamp': group.iloc[-1]['timestamp'],
                            'gocb_ref': gocb_ref,
                            'severity': 'MEDIUM',
                            'message': f'发送间隔波动过大: 标准差 {std_dev:.3f}s, 平均值 {avg_interval:.3f}s'
                        })
    def _detect_stnum_anomalies(self):
        """检测状态号异常"""
        for gocb_ref, group in self.df.groupby('gocb_ref'):
            # 将字符串类型的st_num转换为整数，如果是'N/A'则使用0
            st_nums = [int(st) if st != 'N/A' and st.isdigit() else 0 for st in group['st_num'].values]
            
            # 检查状态号异常变化
            for i in range(1, len(st_nums)):
                if st_nums[i] < st_nums[i-1]:
                    self.anomalies.append({
                        'type': 'STNUM_DECREASE',
                        'timestamp': group.iloc[i]['timestamp'],
                        'gocb_ref': gocb_ref,
                        'severity': 'HIGH',
                        'message': f'状态号异常减少: {st_nums[i-1]} -> {st_nums[i]}'
                    })
                
                # 状态号跳变过大（通常状态号应该逐次增加1）
                if st_nums[i] > st_nums[i-1] + 10:
                    self.anomalies.append({
                        'type': 'STNUM_JUMP',
                        'timestamp': group.iloc[i]['timestamp'],
                        'gocb_ref': gocb_ref,
                        'severity': 'MEDIUM',
                        'message': f'状态号跳极过大: {st_nums[i-1]} -> {st_nums[i]}'
                    })
                
                # 状态号跳变过大（通常状态号应该逐次增加1）
                if st_nums[i] > st_nums[i-1] + 10:
                    self.anomalies.append({
                        'type': 'STNUM_JUMP',
                        'timestamp': group.iloc[i]['timestamp'],
                        'gocb_ref': gocb_ref,
                        'severity': 'MEDIUM',
                        'message': f'状态号跳变过大: {st_nums[i-1]} -> {st_nums[i]}'
                    })
    
    def _detect_test_mode_anomalies(self):
        """检测测试模式异常"""
        test_packets = self.df[self.df['test'] == True]
        if not test_packets.empty:
            for _, row in test_packets.iterrows():
                self.anomalies.append({
                    'type': 'TEST_MODE',
                    'timestamp': row['timestamp'],
                    'gocb_ref': row['gocb_ref'],
                    'severity': 'LOW' if row['nds_com'] else 'HIGH',
                    'message': f'测试模式报文: ndsCom={row["nds_com"]}'
                })
    
    def _detect_config_anomalies(self):
        """检测配置异常"""
        for gocb_ref, group in self.df.groupby('gocb_ref'):
            conf_revs = group['conf_rev'].unique()
            if len(conf_revs) > 1:
                self.anomalies.append({
                    'type': 'CONFIG_CHANGE',
                    'timestamp': group.iloc[-1]['timestamp'],
                    'gocb_ref': gocb_ref,
                    'severity': 'MEDIUM',
                    'message': f'配置版本变化: {conf_revs}'
                })
    
    def _detect_communication_anomalies(self):
        """检测通信异常"""
        # 检查NDSCom标志
        ndscom_packets = self.df[self.df['nds_com'] == True]
        for _, row in ndscom_packets.iterrows():
            self.anomalies.append({
                'type': 'NDSCOM_FLAG',
                'timestamp': row['timestamp'],
                'gocb_ref': row['gocb_ref'],
                'severity': 'MEDIUM',
                'message': 'NDSCom标志置位，表示需要配置'
            })
    
    def _detect_rate_anomalies(self):
        """检测速率异常"""
        total_duration = (self.df['timestamp'].max() - self.df['timestamp'].min()).total_seconds()
        if total_duration > 0:
            packet_rate = len(self.df) / total_duration
            
            # 根据GOOSE典型速率设置阈值
            if packet_rate > 100:  # 100 packets/second
                self.anomalies.append({
                    'type': 'HIGH_RATE',
                    'timestamp': self.df.iloc[-1]['timestamp'],
                    'gocb_ref': 'ALL',
                    'severity': 'MEDIUM',
                    'message': f'报文速率异常高: {packet_rate:.1f} packets/second'
                })
            elif packet_rate < 0.1:  # 0.1 packets/second
                self.anomalies.append({
                    'type': 'LOW_RATE',
                    'timestamp': self.df.iloc[-1]['timestamp'],
                    'gocb_ref': 'ALL',
                    'severity': 'MEDIUM',
                    'message': f'报文速率异常低: {packet_rate:.3f} packets/second'
                })
    
    def generate_report(self):
        """生成异常报告"""
        anomalies_df = pd.DataFrame(self.anomalies)
        
        print("GOOSE异常检测报告")
        print("=" * 60)
        print(f"总报文数: {len(self.df)}")
        print(f"检测到异常数: {len(anomalies_df)}")
        
        if not anomalies_df.empty:
            print("\n异常统计:")
            severity_counts = anomalies_df['severity'].value_counts()
            for severity, count in severity_counts.items():
                print(f"  {severity}: {count}")
            
            print("\n异常类型统计:")
            type_counts = anomalies_df['type'].value_counts()
            for anomaly_type, count in type_counts.items():
                print(f"  {anomaly_type}: {count}")
            
            print("\n详细异常列表:")
            for _, anomaly in anomalies_df.iterrows():
                print(f"[{anomaly['timestamp']}] {anomaly['type']} - {anomaly['severity']}: {anomaly['message']}")
        else:
            print("\n未检测到异常")
        
        return anomalies_df
    
    def plot_anomalies(self):
        """可视化异常"""
        if self.df.empty:
            return
        
        fig, axes = plt.subplots(3, 1, figsize=(12, 10))
        
        # 时序图
        for gocb_ref, group in self.df.groupby('gocb_ref'):
            axes[0].plot(group['timestamp'], group['sq_num'], 
                       marker='o', linestyle='-', label=gocb_ref)
        axes[0].set_title('GOOSE序列号时序图')
        axes[0].set_ylabel('序列号')
        axes[0].legend()
        axes[0].grid(True)
        
        # 时间间隔图
        for gocb_ref, group in self.df.groupby('gocb_ref'):
            time_diffs = group['time_diff'].dropna()
            if not time_diffs.empty:
                # 确保x和y维度匹配
                valid_timestamps = group['timestamp'].iloc[1:1+len(time_diffs)].values
                time_diffs = time_diffs.values
                if len(valid_timestamps) == len(time_diffs):
                    # print(valid_timestamps)
                    # print(time_diffs)
                    axes[1].plot(valid_timestamps, time_diffs, 
                               marker='s', linestyle='-', label=gocb_ref)
                else:
                    print(f"维度不匹配: timestamps({len(valid_timestamps)}), time_diffs({len(time_diffs)})")
        axes[1].set_title('报文时间间隔')
        axes[1].set_ylabel('时间间隔(s)')
        axes[1].grid(True)
        
        # 状态号图
        for gocb_ref, group in self.df.groupby('gocb_ref'):
            axes[2].plot(group['timestamp'], group['st_num'], 
                       marker='^', linestyle='-', label=gocb_ref)
        axes[2].set_title('状态号变化')
        axes[2].set_ylabel('状态号')
        axes[2].set_xlabel('时间')
        axes[2].grid(True)
        
        plt.tight_layout()
        plt.show()

# 使用示例
def main():
    detector = GooseAnomalyDetector('dataset/goose.pcap')
    detector.parse_goose_packets()
    anomalies = detector.detect_anomalies()
    
    report = detector.generate_report()
    detector.plot_anomalies()
    
    # 保存结果到文件
    if not detector.df.empty:
        detector.df.to_csv('goose_analysis.csv', index=False)
    if not report.empty:
        report.to_csv('goose_anomalies.csv', index=False)

if __name__ == "__main__":
    main()