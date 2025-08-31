from goose_publisher import GoosePublisher
from datetime import datetime, timedelta

# 测试GOOSE发布者状态跟踪
print("测试GOOSE发布者状态跟踪")
publisher = GoosePublisher("APP001")
print("初始状态:", publisher.get_status())

# 模拟更新状态
print("更新状态:")
publisher.update_status(1, 1, datetime.now())
print("更新后状态:", publisher.get_status())

# 模拟超时
print("模拟超时")
import time
time.sleep(3)  # 等待超过超时阈值
print("超时检查:", publisher.is_timeout())