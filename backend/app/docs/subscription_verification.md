# 订阅自动检测功能验证指南

## 代码功能分析

### 1. 调度机制
- **调度器类型**: APScheduler BackgroundScheduler
- **检查频率**: 每小时执行一次 `run_subscription_scheduler()`
- **启动时机**: 应用启动时（`@app.on_event("startup")`）

### 2. 执行逻辑
1. 每小时检查所有 `is_active=True` 且 `next_run_at <= now` 的订阅
2. 对每个符合条件的订阅执行 `execute_subscription()`
3. 根据订阅频率计算日期范围：
   - `daily`: 检测最近1天的新增域名
   - `weekly`: 检测最近7天的新增域名
   - `monthly`: 检测最近30天的新增域名
4. 执行检测后，更新 `next_run_at` 为下次执行时间

### 3. 代码流程
```
init_scheduler() 
  → 每小时执行 run_subscription_scheduler()
    → 查询需要执行的订阅 (next_run_at <= now)
      → 对每个订阅执行 execute_subscription()
        → 计算日期范围 _get_date_range_for_frequency()
        → 收集域名数据 _collect_daily_domains()
        → 执行检测（恶意/仿冒）
        → 创建任务记录（Task）
        → 检查阈值，创建预警（Alert）
        → 更新 next_run_at
```

## 验证方法

### 方法1: 查看日志
检查后端日志，应该能看到：
```
订阅调度器已启动
开始执行订阅任务: S{timestamp}
订阅任务 S{timestamp} 执行完成
```

### 方法2: 查看数据库记录
1. **检查 tasks 表**：
   ```sql
   SELECT * FROM tasks 
   WHERE extra LIKE '%subscription_id%' 
   ORDER BY created_at DESC;
   ```
   应该能看到定期创建的任务记录

2. **检查 subscriptions 表**：
   ```sql
   SELECT subscription_id, next_run_at, frequency, is_active 
   FROM subscriptions 
   WHERE is_active = 1;
   ```
   `next_run_at` 应该定期更新

3. **检查 alerts 表**（如果超过阈值）：
   ```sql
   SELECT * FROM alerts 
   ORDER BY created_at DESC;
   ```

### 方法3: 手动触发测试（推荐）
修改数据库中的 `next_run_at` 为过去的时间，让调度器立即执行：

```sql
-- 将某个订阅的 next_run_at 设置为1小时前
UPDATE subscriptions 
SET next_run_at = DATE_SUB(NOW(), INTERVAL 1 HOUR)
WHERE subscription_id = 'S{你的订阅ID}';
```

然后等待最多1小时（调度器每小时检查一次），或者重启服务立即触发。

### 方法4: 创建测试订阅
创建一个频率为 `daily` 的订阅，将 `next_run_at` 设置为几分钟后，观察是否自动执行。

## 服务不运行的问题

### ⚠️ 重要限制
**如果后端服务没有一直运行，被订阅的模型不会执行自动检测！**

原因：
- APScheduler 是内存中的调度器，只在服务运行时工作
- 服务停止后，调度器也停止
- 服务重启后，调度器会重新启动，但**不会补执行**错过的时间

### 解决方案

#### 方案1: 使用系统级定时任务（推荐生产环境）
使用 cron 或 systemd timer 定期调用 API：

```bash
# crontab 示例：每小时执行一次
0 * * * * curl -X POST http://localhost:8000/api/subscriptions/trigger
```

需要添加一个触发端点：
```python
@router.post("/api/subscriptions/trigger")
async def trigger_subscriptions(request: Request):
    """手动触发订阅检查（供cron调用）"""
    run_subscription_scheduler()
    return {"ok": True}
```

#### 方案2: 使用持久化调度器
使用 APScheduler 的持久化功能（需要数据库支持）：
- 使用 `SQLAlchemyJobStore` 存储任务
- 服务重启后可以恢复任务

#### 方案3: 补偿机制
在服务启动时检查是否有错过的订阅：
```python
def check_missed_subscriptions():
    """检查并执行错过的订阅"""
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        # 查找所有 next_run_at 在过去24小时内的订阅
        missed = db.query(Subscription).filter(
            Subscription.is_active == True,
            Subscription.next_run_at <= now,
            Subscription.next_run_at >= now - timedelta(days=1)
        ).all()
        
        for sub in missed:
            execute_subscription(sub.subscription_id)
    finally:
        db.close()
```

## 快速验证步骤

1. **创建测试订阅**：
   - 在前端创建一个订阅（频率选择 daily）
   - 记录订阅ID

2. **修改 next_run_at**：
   ```sql
   UPDATE subscriptions 
   SET next_run_at = DATE_SUB(NOW(), INTERVAL 1 HOUR)
   WHERE subscription_id = '你的订阅ID';
   ```

3. **查看日志**：
   ```bash
   # 查看后端日志
   tail -f logs/app.log | grep -i subscription
   ```

4. **等待或重启服务**：
   - 等待最多1小时让调度器执行
   - 或重启服务立即触发（如果实现了启动时检查）

5. **验证结果**：
   - 检查 tasks 表是否有新记录
   - 检查 subscriptions 表的 next_run_at 是否更新
   - 检查是否有预警记录（如果超过阈值）

## 建议

1. **生产环境**：使用系统级定时任务（cron）更可靠
2. **开发环境**：可以手动触发或修改 next_run_at 测试
3. **监控**：添加监控告警，确保调度器正常运行
4. **日志**：确保日志级别足够，能看到调度器执行情况

