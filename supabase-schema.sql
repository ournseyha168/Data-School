create table if not exists public.school_storage (
    id text primary key,
    data jsonb not null default '{}'::jsonb,
    updated_at timestamptz not null default now()
);

create table if not exists public.managed_accounts (
    username text primary key,
    password_hash text not null,
    role text not null check (role in ('admin', 'user')),
    created_by text not null check (created_by in ('owner', 'admin')),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create or replace function public.touch_managed_accounts_updated_at()
returns trigger
language plpgsql
as $$
begin
    new.updated_at = now();
    return new;
end;
$$;

drop trigger if exists managed_accounts_updated_at on public.managed_accounts;
create trigger managed_accounts_updated_at
before update on public.managed_accounts
for each row execute function public.touch_managed_accounts_updated_at();

alter table public.managed_accounts enable row level security;
revoke all on table public.managed_accounts from anon, authenticated;

alter table public.school_storage enable row level security;

revoke all on table public.school_storage from anon, authenticated;

create or replace function public.touch_school_storage_updated_at()
returns trigger
language plpgsql
as $$
begin
    new.updated_at = now();
    return new;
end;
$$;

drop trigger if exists school_storage_updated_at on public.school_storage;
create trigger school_storage_updated_at
before update on public.school_storage
for each row execute function public.touch_school_storage_updated_at();

insert into storage.buckets (id, name, public)
values ('school-files', 'school-files', true)
on conflict (id) do update set public = excluded.public;

-- Managed Admin/User passwords are stored as scrypt hashes by server.js.
-- The Supabase service key is server-only; do not expose it in the browser.
