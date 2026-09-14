create table if not exists public.school_storage (
    id text primary key,
    data jsonb not null default '{}'::jsonb,
    updated_at timestamptz not null default now()
);

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
