import json
from datetime import datetime
from flask import Flask, jsonify
from goosecatch import *
from SCDana import *
#from modelana import *
from test_modelana import *
app = Flask(__name__)

# 全局监控器实例
monitor = GooseMonitor()
scd_parser = ScdParser('station.scd')


@app.route('/check_goose_links', methods=['GET'])
def check_goose_links():
    """一键检测GOOSE链路状态接口"""
    try:
        # 1. 获取当前GOOSE发布者状态
        active_publishers = []
        for app_id, publisher in monitor.publishers.items():
            if not publisher.is_timeout():
                active_publishers.append({
                    'app_id': app_id,
                    'last_update': publisher.last_update.isoformat(),
                    'st_num': publisher.last_st_num,
                    'sq_num': publisher.last_sq_num
                })

        # 2. 获取当前GOOSE连接关系(简化为从SCD获取)
        scd_connections = scd_parser.get_goose_connections()

        # 3. 验证链路状态、Ai模型评价
        validation_issues = scd_parser.validate_goose_links(active_publishers)
        #modeldation_issues = predict_anomaly(active_publishers)
        modeldation_issues = test_predict_anomaly(active_publishers)

        # 4. 生成链路评价报告
        report = {
            'timestamp': datetime.now().isoformat(),
            'active_publishers': active_publishers,
            'configured_connections': scd_connections,
            'issues': validation_issues,
            'modeldation_issues': modeldation_issues,
            'summary': {
                'total_configured': len(scd_connections),
                'active_connections': len(active_publishers),
                'missing_connections': len([i for i in validation_issues if i['type'] == 'missing']),
                'unexpected_connections': len([i for i in validation_issues if i['type'] == 'unexpected'])
            }
        }
        print(report)
        return jsonify(report)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # 启动GOOSE监控线程
    print("启动GOOSE监控线程")
    import threading

    monitor_thread = threading.Thread(target=monitor.start_monitoring)
    monitor_thread.daemon = True
    monitor_thread.start()

    # 启动Web服务
    print("启动Web可视化服务")
    app.run(host='0.0.0.0', port=5000)