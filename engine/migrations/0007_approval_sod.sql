-- Separation of duties for exception approvals.
--
-- An exception now starts as a `pending` request from one principal and must be
-- approved by a *different* admin before it grants. Until approval the approver
-- and expiry are unknown, so both become nullable, and the requested TTL is
-- stored so expiry is computed at approval time (the exception window starts when
-- it is approved, not when it was requested).

ALTER TABLE approvals ALTER COLUMN approver_id DROP NOT NULL;
ALTER TABLE approvals ALTER COLUMN expires_at DROP NOT NULL;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS ttl_hours BIGINT;

ALTER TABLE approvals DROP CONSTRAINT IF EXISTS approvals_status_check;
ALTER TABLE approvals ADD CONSTRAINT approvals_status_check
  CHECK (status IN ('pending', 'active', 'expired', 'revoked', 'rejected'));
