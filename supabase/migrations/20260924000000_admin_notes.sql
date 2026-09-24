-- =====================================================================
--  ADMIN MESSAGE TO THE REPORTER
--  ---------------------------------------------------------------------
--  Adds the two columns behind the "Message to the reporter" box that an
--  administrator can fill in when editing / fixing an issue. The person
--  who reported the issue then sees the message on their own issue.
--
--  Safe to run more than once. The same columns are already included in
--  ../supabase-schema.sql and in the SQL embedded in index.html — if you
--  change one, change all three.
--
--  CLI:      supabase db push
--  Or paste this into the SQL Editor and press Run.
-- =====================================================================

alter table public.issues add column if not exists admin_note    text        not null default '';
alter table public.issues add column if not exists admin_note_at timestamptz not null default 'epoch';
