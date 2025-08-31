import requests
import json

# 定义测试服务器URL
BASE_URL = 'http://127.0.0.1:5000'

def test_check_goose_links():
    # 发送GET请求到/check_goose_links端点
    response = requests.get(f'{BASE_URL}/check_goose_links')
    
    # 检查HTTP状态码
    assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
    
    # 解析响应内容
    print("响应内容:")
    data = response.json()
    print(data)
    
    # 检查响应内容是否符合预期
    print("检查响应内容是否符合预期")

    assert isinstance(data, dict), "Expected JSON object, got something else"
    assert 'timestamp' in data, "Expected 'timestamp' in response"
    assert 'active_publishers' in data, "Expected 'active_publishers' in response"
    assert 'configured_connections' in data, "Expected 'configured_connections' in response"
    assert 'issues' in data, "Expected 'issues' in response"
    assert 'summary' in data, "Expected 'summary' in response"
    
    # 进一步验证每个字段的类型和内容
    assert isinstance(data['timestamp'], str), "Expected 'timestamp' to be a string"
    assert isinstance(data['active_publishers'], list), "Expected 'active_publishers' to be a list"
    assert isinstance(data['configured_connections'], list), "Expected 'configured_connections' to be a list"
    assert isinstance(data['issues'], list), "Expected 'issues' to be a list"
    assert isinstance(data['summary'], dict), "Expected 'summary' to be a dictionary"
    
    # 根据需要添加更多断言来验证具体的业务逻辑
    # 例如，验证'summary'中的字段是否符合预期
    assert 'total_configured' in data['summary'], "Expected 'total_configured' in summary"
    assert 'active_connections' in data['summary'], "Expected 'active_connections' in summary"
    assert 'missing_connections' in data['summary'], "Expected 'missing_connections' in summary"
    assert 'unexpected_connections' in data['summary'], "Expected 'unexpected_connections' in summary"
    
    # 打印测试结果（可选）
    print("无异常抛出,Test passed!测试通过")

if __name__ == '__main__':
    test_check_goose_links()