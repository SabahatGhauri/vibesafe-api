-- VibeSafe scan analytics — privacy-safe event tracking (metadata only, never code).
-- Captures scans from BOTH the website dashboard and the VS Code / Cursor extension,
-- tagged by source, so you can compare channels and success/fail ratios.

create table if not exists extension_events (
  id                uuid primary key default gen_random_uuid(),
  user_id           uuid,
  event             text not null,          -- scan_success, scan_failed, api_key_saved, invalid_api_key, session_expired, extension_connected
  source            text default 'extension', -- 'website' | 'vscode_extension' | 'github_action'
  scan_type         text,                    -- 'code' | 'github_url' | 'live_url'
  extension_version text,
  editor            text,                   -- 'vscode' | 'cursor' | 'website'
  language          text,
  score             int,
  issues            int,
  success           boolean,
  error_message     text,
  created_at        timestamptz default now()
);

-- Add columns to an existing table if it predates this version.
alter table extension_events add column if not exists source text default 'extension';
alter table extension_events add column if not exists scan_type text;

create index if not exists idx_ext_events_created on extension_events (created_at desc);
create index if not exists idx_ext_events_user on extension_events (user_id);
create index if not exists idx_ext_events_source on extension_events (source);

alter table extension_events enable row level security;
-- No public policies: rows are written server-side (service role) and read only
-- through the admin stats function below.

-- Admin-only aggregate report. SECURITY DEFINER so it reads all rows, but returns
-- ONLY counts/aggregates (never raw events), and only for the owner account.
create or replace function get_extension_stats()
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  result json;
begin
  if coalesce(auth.jwt() ->> 'email', '') not in ('sabahatghauri10@gmail.com', 'contact@vibesafe.info') then
    return json_build_object('error', 'not authorized');
  end if;

  with scans as (
    select * from extension_events where event in ('scan_success','scan_failed')
  )
  select json_build_object(
    -- People
    'total_users',     (select count(distinct user_id) from scans),
    'active_today',    (select count(distinct user_id) from scans where created_at >= now() - interval '1 day'),
    'active_7d',       (select count(distinct user_id) from scans where created_at >= now() - interval '7 days'),
    'active_30d',      (select count(distinct user_id) from scans where created_at >= now() - interval '30 days'),
    'users_website',   (select count(distinct user_id) from scans where source = 'website'),
    'users_extension', (select count(distinct user_id) from scans where source = 'extension'),

    -- Scans overall
    'scans_total',     (select count(*) from scans),
    'scans_today',     (select count(*) from scans where created_at >= now() - interval '1 day'),
    'scans_success',   (select count(*) from scans where event = 'scan_success'),
    'scans_failed',    (select count(*) from scans where event = 'scan_failed'),
    'success_rate',    (select case when count(*)=0 then null
                          else round(100.0 * count(*) filter (where event='scan_success') / count(*)) end from scans),

    -- By source
    'website_total',   (select count(*) from scans where source='website'),
    'website_success', (select count(*) from scans where source='website' and event='scan_success'),
    'website_failed',  (select count(*) from scans where source='website' and event='scan_failed'),
    'ext_total',       (select count(*) from scans where source='extension'),
    'ext_success',     (select count(*) from scans where source='extension' and event='scan_success'),
    'ext_failed',      (select count(*) from scans where source='extension' and event='scan_failed'),

    'connected_extensions', (select count(distinct user_id) from extension_events where event='api_key_saved'),

    -- By scan type (code / github_url / live_url)
    'by_scan_type', (
        select coalesce(json_agg(row_to_json(t)), '[]'::json) from (
          select coalesce(scan_type,'code') as scan_type, count(*) as n,
                 count(*) filter (where event='scan_success') as ok,
                 count(*) filter (where event='scan_failed')  as fail
          from scans group by coalesce(scan_type,'code') order by n desc
        ) t),

    'top_errors', (
        select coalesce(json_agg(row_to_json(e)), '[]'::json) from (
          select error_message, source, count(*) as n
          from scans where event='scan_failed' and error_message is not null
          group by error_message, source order by n desc limit 6
        ) e),
    'top_languages', (
        select coalesce(json_agg(row_to_json(l)), '[]'::json) from (
          select language, count(*) as n
          from scans where event='scan_success' and language is not null
          group by language order by n desc limit 6
        ) l),
    'versions', (
        select coalesce(json_agg(row_to_json(v)), '[]'::json) from (
          select extension_version, count(distinct user_id) as users
          from extension_events
          where extension_version is not null and created_at >= now() - interval '30 days'
          group by extension_version order by users desc limit 6
        ) v)
  ) into result;
  return result;
end;
$$;

grant execute on function get_extension_stats() to authenticated;
