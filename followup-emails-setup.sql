-- Follow-up emails: one per user, sent the day after their first scan if they
-- haven't upgraded (see api/scan-followup.js, triggered by Vercel Cron daily).
create table if not exists followup_emails (
  user_id  uuid primary key,
  sent_at  timestamptz default now()
);
alter table followup_emails enable row level security;

drop function if exists get_followup_candidates();
create or replace function get_followup_candidates()
returns json
language plpgsql
security definer
set search_path = public
as $$
declare result json;
begin
  select coalesce(json_agg(row_to_json(t)), '[]'::json) into result from (
    select
      e.user_id,
      u.email,
      min(e.created_at) as first_scan,
      (select e2.score from extension_events e2
         where e2.user_id = e.user_id and e2.event = 'scan_success' and e2.score is not null
         order by e2.created_at desc limit 1) as last_score,
      (select e2.issues from extension_events e2
         where e2.user_id = e.user_id and e2.event = 'scan_success' and e2.issues is not null
         order by e2.created_at desc limit 1) as last_issues
    from extension_events e
    join auth.users u on u.id = e.user_id
    where e.event = 'scan_success'
      and e.user_id is not null
      and not exists (select 1 from followup_emails f where f.user_id = e.user_id)
      and coalesce((select p.plan from vibesafe_plans p where p.id = e.user_id), 'free') = 'free'
    group by e.user_id, u.email
    having min(e.created_at) < now() - interval '20 hours'
       and min(e.created_at) > now() - interval '30 days'
    limit 50
  ) t;
  return result;
end;
$$;
revoke execute on function get_followup_candidates() from public, anon, authenticated;
