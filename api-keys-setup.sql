-- VibeSafe API keys — lets the VS Code extension authenticate with a long-lived key
-- instead of a short-lived Supabase session token.

create table if not exists vibesafe_api_keys (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references auth.users(id) on delete cascade,
  key         text not null unique,
  name        text default 'VS Code extension',
  created_at  timestamptz default now(),
  last_used_at timestamptz
);

alter table vibesafe_api_keys enable row level security;

-- A logged-in user manages only their own keys (used by the dashboard UI).
drop policy if exists "own api keys" on vibesafe_api_keys;
create policy "own api keys" on vibesafe_api_keys
  for all
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- SECURITY DEFINER lookup: the scan API resolves an API key to a user id without
-- exposing the whole table. Also stamps last_used_at so you can see activity.
create or replace function get_user_by_api_key(k text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  uid uuid;
begin
  update vibesafe_api_keys
     set last_used_at = now()
   where key = k
   returning user_id into uid;
  return uid;
end;
$$;

-- Let the anon role call the resolver (it only returns a uuid, never the key list).
grant execute on function get_user_by_api_key(text) to anon;
