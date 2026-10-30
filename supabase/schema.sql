-- Cyber-SentinelBaran1886 — Supabase (PostgreSQL) schema
-- شغّل هذا الملف مرة واحدة في Supabase → SQL Editor.
-- © 2026 Baran Avisat — MIT

create table if not exists public.scans (
  scan_id        text primary key,
  target         text not null,
  mode           text not null default 'all',
  score          int  not null default 0,
  grade          text not null default 'F',
  counts         jsonb not null default '{}'::jsonb,
  ai_provider    text not null default 'off',
  engine_versions jsonb not null default '{}'::jsonb,
  findings_count int not null default 0,
  finished_at    timestamptz not null default now(),
  created_at     timestamptz not null default now()
);

create table if not exists public.findings (
  id          bigserial primary key,
  scan_id     text not null references public.scans(scan_id) on delete cascade,
  key         text not null,
  rule_id     text not null,
  title       text not null,
  severity    text not null check (severity in ('critical','high','medium','low','info')),
  category    text not null,
  location    text default '',
  evidence    text default '',   -- always redacted before it leaves the scanner
  owasp       text default '',
  remediation text default '',
  ai_fix      text default '',
  cvss        numeric(3,1) not null default 0,
  created_at  timestamptz not null default now(),
  unique (scan_id, key)
);

create index if not exists findings_sev_idx on public.findings (scan_id, severity);
create index if not exists scans_time_idx   on public.scans (finished_at desc);

-- متوسط الدرجة آخر 30 يوماً (يستخدمه اللوحة)
create or replace view public.score_trend as
select scan_id, target, score, grade, finished_at
from public.scans
where finished_at > now() - interval '30 days'
order by finished_at asc;

alter table public.scans     enable row level security;
alter table public.findings  enable row level security;

-- لا وصول من المتصفح إطلاقاً: يُكتب ويقرأ من الخادم بمفتاح service_role فقط.
create policy "no anon read scans"     on public.scans    for select to anon using (false);
create policy "no anon read findings"  on public.findings for select to anon using (false);
