-- Product fitment (vehicle compatibility) schema.
--
-- Apply this file to the database before expecting /products to return the
-- `fitments` array. Using psql with the DATABASE_URL from .env:
--   psql "$DATABASE_URL" -f schema-fitments.sql
-- Or from inside an interactive psql session:
--   \i schema-fitments.sql
-- Re-running is safe: the IF NOT EXISTS guards make it idempotent.
--
-- One product can fit many vehicle configurations. `brand` is required
-- (e.g. "BMW"); series/model/engine narrow the match and are optional.

CREATE TABLE IF NOT EXISTS product_fitments (
  id bigserial PRIMARY KEY,
  product_id bigint NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  brand text NOT NULL,
  series text,
  model text,
  engine text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_fitments_product ON product_fitments (product_id);

-- ------------------------------------------------------------------
-- Sample data for verification.
--
-- Attaches two BMW fitments to the demo product with SKU
-- 'BC-COILOVER-DEMO' when that product exists. The NOT EXISTS guard keeps
-- the seed idempotent so re-running the file does not duplicate rows.
-- ------------------------------------------------------------------

INSERT INTO product_fitments (product_id, brand, series, model, engine)
SELECT p.id, v.brand, v.series, v.model, v.engine
FROM products p
JOIN (
  VALUES
    ('BMW', '3 Series', NULL::text, NULL::text),
    ('BMW', '5 Series', NULL::text, NULL::text)
) AS v(brand, series, model, engine) ON TRUE
WHERE p.sku = 'BC-COILOVER-DEMO'
  AND NOT EXISTS (
    SELECT 1 FROM product_fitments f
    WHERE f.product_id = p.id
      AND f.brand = v.brand
      AND f.series IS NOT DISTINCT FROM v.series
      AND f.model IS NOT DISTINCT FROM v.model
      AND f.engine IS NOT DISTINCT FROM v.engine
  );
