-- Run once in Supabase -> SQL Editor -> New query -> Run. Safe to run again.
create table if not exists users(
  sub text primary key, email text not null, name text, label text,
  wtoken text unique not null,
  cookie_enc text, cookie_expires timestamptz,
  status text default 'new', last_fetch timestamptz, last_seen timestamptz,
  created_at timestamptz default now());
create table if not exists logs(id bigserial primary key, t timestamptz default now(), user_label text, level text, msg text, ms int);
create index if not exists logs_t on logs(t);
-- old versions stored schedule data here; remove it if present
alter table users drop column if exists cache, drop column if exists cache_at;
alter table users add column if not exists override_date text, add column if not exists lunch_on boolean default true, add column if not exists lunch_start text, add column if not exists lunch_end text;
-- RLS on with NO policies: the public anon key can read nothing. Only the server's secret/service key can.
alter table users enable row level security;
alter table logs enable row level security;
