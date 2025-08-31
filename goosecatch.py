import pyshark
# pyshark.FileCapture.set_debug()
# pyshark.FileCapture.tshark_path = 'G:\\Wireshark\\TShark.exe'
from goose_publisher import GoosePublisher
from datetime import datetime

class GooseMonitor:
    def __init__(self, interface='eth0'):
        self.interface = interface
        self.capture = pyshark.LiveCapture(
            interface=interface,
            display_filter='goose'
        )
        self.publishers = {}

    def start_monitoring(self):
        """开始捕获GOOSE报文"""
        print(f"Starting GOOSE monitoring on {self.interface}")
        self.capture.apply_on_packets(self.packet_handler)

    def packet_handler(self, pkt):
        """处理捕获的GOOSE报文"""
        try:
            goose = pkt.goose
            app_id = goose.appid
            st_num = goose.stnum
            sq_num = goose.sqnum
            timestamp = pkt.sniff_time

            # 记录发布者状态
            if app_id not in self.publishers:
                self.publishers[app_id] = GoosePublisher(app_id)

            publisher = self.publishers[app_id]
            publisher.update_status(st_num, sq_num, timestamp)

            # 检查心跳超时
            if publisher.is_timeout():
                print(f"警告: GOOSE发布者 {app_id} 心跳超时!")

        except AttributeError as e:
            print(f"报文解析错误: {e}")


class GoosePublisher:
    """GOOSE发布者状态跟踪"""

    def __init__(self, app_id):
        self.app_id = app_id
        self.last_st_num = None
        self.last_sq_num = None
        self.last_update = None
        self.timeout = 2.0  # 心跳超时阈值(秒)

    def update_status(self, st_num, sq_num, timestamp):
        """更新发布者状态"""
        self.last_st_num = st_num
        self.last_sq_num = sq_num
        self.last_update = timestamp

    def is_timeout(self):
        """检查是否心跳超时"""
        if not self.last_update:
            return False
        return (datetime.now() - self.last_update).total_seconds() > self.timeout