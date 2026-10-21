-- Server-side shopping cart schema.
--
-- Apply this file to the database before using the /cart endpoints.
-- Using psql with the DATABASE_URL from .env:
--   psql "$DATABASE_URL" -f schema-cart.sql
-- Or from inside an interactive psql session:
--   \i schema-cart.sql
-- Re-running is safe: the IF NOT EXISTS guards make it idempotent.
--
-- cart_items is keyed directly by user_id (one cart per user, no separate
-- carts table needed). This matches the existing live database shape.

CREATE TABLE IF NOT EXISTS cart_items (
  id bigserial PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  product_id bigint NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  quantity int NOT NULL DEFAULT 1 CHECK (quantity > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, product_id)
);

CREATE INDEX IF NOT EXISTS idx_cart_user ON cart_items (user_id);
