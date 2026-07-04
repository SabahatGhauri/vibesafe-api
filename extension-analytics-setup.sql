-- VibeSafe extension analytics — privacy-safe event tracking (metadata only, never code).

create table if not exists extension_events (
  id                uuid primary key default gen_random_uuid(),
  user_id           uuid,
  event             text not null,          -- scan_started, scan_success, scan_failed, api_key_saved, invalid_api_key, session_expired, extension_connected
  extension_version text,
  editor            text,                   -- 'vscode' | 'cursor' | etc
  language          text,
  score             int,
  issues            int,
  success           boolean,
  error_message     text,
  created_at        timestamptz default now()
);

create index if not exists idx_ext_events_created on extension_events (created_at desc);
create index if not exists idx_ext_events_user on extension_events (user_id);

alter table extension_events enable row level security;
-- No public policies: events are written server-side (service role) and read only
-- through the admin stats function below.

-- Admin-only aggregate stats. SECURITY DEFINER so it can read all rows, but it
-- returns ONLY counts/aggregates (never raw events), and only for the owner account.
create or replace function get_extension_stats()
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  result json;
begin
  -- Lock this down to the founder account(s). Add emails as needed.
  if coalesce(auth.jwt() ->> 'email', '') not in ('sabahatghauri10@gmail.com', 'contact@vibesafe.info') then
    return json_build_object('error', 'not authorized');
  end if;

  select json_build_object(
    'active_today',    (select count(distinct user_id) from extension_events where created_at >= now() - interval '1 day'),
    'active_7d',       (select count(distinct user_id) from extension_events where created_at >= now() - interval '7 days'),
    'active_30d',      (select count(distinct user_id) from extension_events where created_at >= now() - interval '30 days'),
    'scans_today',     (select count(*) from extension_events where event = 'scan_success' and created_at >= now() - interval '1 day'),
    'scans_total',     (select count(*) from extension_events where event = 'scan_success'),
    'scans_failed',    (select count(*) from extension_events where event = 'scan_failed'),
    'success_rate',    (
        select case when (s+f) = 0 then null else round(100.0 * s / (s+f)) end
        from (select
          (select count(*) from extension_events where event='scan_success') as s,
          (select count(*) from extension_events where event='scan_failed')  as f
        ) t),
    'installs',        (select count(*) from extension_events where event = 'api_key_saved'),
    'top_errors', (
        select coalesce(json_agg(row_to_json(e)), '[]'::json) from (
          select error_message, count(*) as n
          from extension_events
          where event = 'scan_failed' and error_message is not null
          group by error_message order by n desc limit 5
        ) e),
    'top_languages', (
        select coalesce(json_agg(row_to_json(l)), '[]'::json) from (
          select language, count(*) as n
          from extension_events
          where event = 'scan_success' and language is not null
          group by language order by n desc limit 5
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
