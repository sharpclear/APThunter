import json

# 测试JSON解析
s = '[{"provider": "AWS", "count": 100}]'
parsed = json.loads(s)
print(f"Type: {type(parsed)}")
print(f"Value: {parsed}")
print(f"First item type: {type(parsed[0])}")

# 测试FastAPI返回
result = {
    "code": 200,
    "data": {
        "vpsProviders": parsed
    }
}
print(f"\nResult: {result}")
