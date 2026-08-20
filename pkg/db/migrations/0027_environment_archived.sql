-- An environment can be retired from the compliance picture without being
-- deleted.
--
-- Control coverage divides by count(*) of environments, so every environment
-- that ever existed sits in the denominator forever. The e2e suite creates one
-- per run (scripts/servicenow-e2e.sh, "Fides e2e, safe to delete") and deletes
-- nothing, so five abandoned runs had pushed DORA coverage to 6/15 = 40% while
-- the real figure across real environments was 6/10. A number that drops every
-- Monday because a test ran is not a compliance signal.
--
-- Deleting was not the answer: an environment owns snapshots, allowlists and
-- policies that are evidence, and evidence does not get deleted to make a
-- percentage look better. Archiving keeps the row and every child record, and
-- only takes it out of the coverage denominator and the default listing.
--
-- Default FALSE, so no existing environment changes behaviour on upgrade, and
-- an archived environment still resolves by id -- snapshots, policy checks and
-- allowlists against it keep working exactly as before.
ALTER TABLE environments
    ADD COLUMN IF NOT EXISTS archived BOOLEAN NOT NULL DEFAULT FALSE;
