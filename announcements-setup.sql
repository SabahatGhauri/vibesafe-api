-- VibeSafe broadcast — announcements shown inside the VS Code extension on startup.
-- Admins create them from the dashboard; the extension reads the active one via
-- /api/announcement (service role, server-side). Only one is active at a time.

create table if not exists announcements (
  id         uuid primary key default gen_random_uuid(),
  message    text not null,
  cta_label  text,
  cta_url    text,
  audience   text default 'all',   -- 'all' | 'connected' | 'unconnected'
  active     boolean default true,
  created_at timestamptz default now()
);
create index if not exists idx_announcements_active on announcements (active, created_at desc);

alter table announcements enable row level security;

-- Admins can create/manage announcements from the dashboard.
drop policy if exists "admins manage announcements" on announcements;
create policy "admins manage announcements" on announcements
  for all to authenticated
  using (coalesce(auth.jwt() ->> 'email','') in ('sabahatghauri10@gmail.com','contact@vibesafe.info'))
  with check (coalesce(auth.jwt() ->> 'email','') in ('sabahatghauri10@gmail.com','contact@vibesafe.info'));
