-- Step 2.1 follow-up: schedule domains that were never scheduled (docs/plan/steps/03-domain-onboarding.md
-- D11, D12).
--
-- 20261102091717_domain_onboarding added `domains.next_check_at` as NULL for every existing row.
-- The api's domain-check job only picks up rows with `next_check_at <= now`, so a domain that
-- existed before step 2.1 (e.g. the seeded demo domain, or a pending claim) was never checked:
-- its configuration pass (D12: ownership record, DKIM key, DNS record rows) never ran and it
-- was never re-verified.
--
-- Every status the job checks (pending_verification, verified, active, suspended) always has a
-- next_check_at once the job has seen it (D11), so NULL in those statuses means "never
-- scheduled". Those rows become due now; the first tick materializes their configuration and
-- reschedules them. failed, deleted and the deprecated disabled stay NULL (never checked).
--
-- Data only, no DDL: no schema drift. Idempotent (a second run matches no row). Uses the
-- domains_next_check_at_idx index for the NULL test; `domains` is small (hundreds to thousands
-- of rows) and only the matched rows are locked.
UPDATE `domains`
SET `next_check_at` = CURRENT_TIMESTAMP(3)
WHERE `next_check_at` IS NULL
  AND `status` IN ('pending_verification', 'verified', 'active', 'suspended');
