from datetime import datetime, timedelta

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
            return True
        return (datetime.now() - self.last_update).total_seconds() > self.timeout

    def get_status(self):
        """获取当前状态"""
        return {
            'app_id': self.app_id,
            'st_num': self.last_st_num,
            'sq_num': self.last_sq_num,
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'is_timeout': self.is_timeout()
        }