-- True code-to-prod lead time (issue #301). The author/committer timestamp of a
-- trail's git commit, so DORA lead time can be measured from when the change was
-- committed rather than from when the trail (pipeline) was created. Nullable —
-- the lead-time query falls back to created_at when it is not populated.
ALTER TABLE trails ADD COLUMN IF NOT EXISTS git_committed_at TIMESTAMP WITH TIME ZONE;
