-- Welcome emails: one per user, sent within a day of signup by the daily
-- scan-followup cron (see api/scan-followup.js). Mirrors followup-emails-setup.sql.
create table if not exists welcome_emails (
  user_id  uuid primary key,
  sent_at  timestamptz default now()
);
alter table welcome_emails enable row level security;

drop function if exists get_welcome_candidates();
create or replace function get_welcome_candidates()
returns json
language plpgsql
security definer
set search_path = public
as $$
declare result json;
begin
  select coalesce(json_agg(row_to_json(t)), '[]'::json) into result from (
    select u.id as user_id, u.email
    from auth.users u
    where u.email is not null
      and u.created_at > now() - interval '7 days'
      and not exists (select 1 from welcome_emails w where w.user_id = u.id)
    order by u.created_at
    limit 50
  ) t;
  return result;
end;
$$;
revoke execute on function get_welcome_candidates() from public, anon, authenticated;

-- Accounts that predate this feature should not get a "welcome" email weeks
-- after they signed up — mark them as already welcomed.
insert into welcome_emails (user_id)
select id from auth.users
on conflict (user_id) do nothing;
