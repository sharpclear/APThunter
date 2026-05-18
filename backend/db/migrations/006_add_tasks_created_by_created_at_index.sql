-- Improve task-list pagination by supporting WHERE created_by + ORDER BY created_at.
CREATE INDEX idx_tasks_created_by_created_at ON tasks (created_by, created_at);
