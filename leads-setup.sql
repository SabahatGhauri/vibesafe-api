-- VibeSafe lead capture — emails from interested visitors, to convert to Pro later.
-- Privacy-safe: email + where/what they opted in for. Anyone can submit; only admins read.

create table if not exists leads (
  id         uuid primary key default gen_random_uuid(),
  email      text not null,
  name       text,
  source     text,        -- 'homepage' | 'checklist' | 'extension' | 'scan_result' | ...
  magnet     text,        -- what they opted in for
  note       text,
  converted  boolean default false,
  created_at timestamptz default now()
);
alter table leads add column if not exists name text;
create index if not exists idx_leads_created on leads (created_at desc);

alter table leads enable row level security;

-- Public pages (anon) can submit a lead; nobody can read rows directly.
drop policy if exists "anyone can submit a lead" on leads;
create policy "anyone can submit a lead" on leads
  for insert to anon, authenticated
  with check (email is not null and length(email) <= 200);

-- Admin-only read: aggregates + recent leads, owner accounts only.
drop function if exists get_leads();
create or replace function get_leads()
returns json
language plpgsql
security definer
set search_path = public
as $$
declare result json;
begin
  if coalesce(auth.jwt() ->> 'email', '') not in ('sabahatghauri10@gmail.com', 'contact@vibesafe.info') then
    return json_build_object('error', 'not authorized');
  end if;
  select json_build_object(
    'total',      (select count(distinct lower(email)) from leads),
    'today',      (select count(*) from leads where created_at >= now() - interval '1 day'),
    'last_7d',    (select count(*) from leads where created_at >= now() - interval '7 days'),
    'converted',  (select count(*) from leads where converted),
    'by_source', (
        select coalesce(json_agg(row_to_json(s)), '[]'::json) from (
          select coalesce(source,'unknown') as source, count(*) as n
          from leads group by coalesce(source,'unknown') order by n desc limit 10
        ) s),
    'recent', (
        select coalesce(json_agg(row_to_json(r)), '[]'::json) from (
          select name, email, source, magnet, converted, created_at
          from leads order by created_at desc limit 100
        ) r)
  ) into result;
  return result;
end;
$$;
grant execute on function get_leads() to authenticated;
