
-- Profiles: one row per auth user; flag admins.
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  is_admin boolean not null default false,
  created_at timestamptz not null default now()
);

-- Found items submitted by students; admins approve/deny; later marked returned.
create table if not exists public.items (
  id bigint generated always as identity primary key,
  title text not null,
  description text,
  place_found text,
  photo_url text,
  found_by uuid not null references auth.users(id) on delete cascade,
  status text not null check (status in ('submitted','approved','rejected','returned')),
  approved_by uuid references auth.users(id),
  approved_at timestamptz,
  rejected_reason text,
  returned_to uuid references auth.users(id),
  returned_at timestamptz,
  created_at timestamptz not null default now()
);

-- Student claims for approved items; admin validates.
create table if not exists public.claims (
  id bigint generated always as identity primary key,
  item_id bigint not null references public.items(id) on delete cascade,
  claimer_id uuid not null references auth.users(id) on delete cascade,
  status text not null check (status in ('pending','approved','denied')),
  admin_id uuid references auth.users(id),
  note text,
  decided_at timestamptz,
  created_at timestamptz not null default now()
);

-- Prevent multiple pending claims per item (optional).
create unique index if not exists claims_one_pending_per_item
  on public.claims (item_id)
  where status = 'pending';
