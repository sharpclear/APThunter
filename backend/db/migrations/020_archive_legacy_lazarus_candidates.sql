-- 归档直接入库策略启用前遗留的 Lazarus.day 待审核候选。
-- 这些记录没有关联正式事件；保留 payload 和原审核原因，仅收敛其终态。
UPDATE apt_event_candidates
SET decision = 'rejected',
    decision_reason = CONCAT(
        '历史候选已归档：生成于直接入库策略启用前，且未形成正式事件；',
        COALESCE(NULLIF(decision_reason, ''), '原审核原因未记录')
    )
WHERE source = 'lazarus.day'
  AND decision = 'needs_review'
  AND apt_event_id IS NULL
  AND event_managed = 0
  AND first_seen_at < '2026-08-19 00:00:00';
