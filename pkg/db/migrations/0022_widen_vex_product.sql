-- Widen vex_statements.product so it can hold a full package URL (purl), now
-- that a VEX statement can be scoped to a component purl (#310). purls (e.g.
-- Maven coordinates with qualifiers) can exceed the original VARCHAR(128);
-- sbom_components.purl is VARCHAR(512), so match it.
ALTER TABLE vex_statements ALTER COLUMN product TYPE VARCHAR(512);
