
-- Enable RLS
alter table public.profiles enable row level security;
alter table public.items    enable row level security;
alter table public.claims   enable row level security;

-- Helper: "is current user admin?"
-- We'll use this predicate inside policies.
-- (No function required; we use EXISTS in policy predicates.)

/* PROFILES policies */
-- Users can view and update their own profile.
create policy "Profiles: self select"
  on public.profiles for select to authenticated
  using (id = auth.uid());

create policy "Profiles: self update"
  on public.profiles for update to authenticated
  using (id = auth.uid());

-- Admins can select all profiles.
create policy "Profiles: admin select all"
  on public.profiles for select to authenticated
  using (
    exists (
      select 1 from public.profiles p
      where p.id = auth.uid() and p.is_admin = true
    )
  );

/* ITEMS policies */
-- Anyone signed in can see approved items; owners can see their own submissions; admins can see everything.
create policy "Items: select approved or own or admin"
  on public.items for select to authenticated
  using (
    status = 'approved'
    or found_by = auth.uid()
    or exists (
      select 1 from public.profiles p
      where p.id = auth.uid() and p.is_admin = true
    )
  );

-- Students can submit (insert) their own found items.
create policy "Items: insert own"
  on public.items for insert to authenticated
  with check (found_by = auth.uid());

-- Students can edit their own item while not yet approved (optional: allow edit if rejected too).
create policy "Items: update own while pending/rejected"
  on public.items for update to authenticated
  using (found_by = auth.uid() and status in ('submitted','rejected'));

-- Admins can approve/deny/mark returned on any item.
create policy "Items: admin update all"
  on public.items for update to authenticated
  using (
    exists (
      select 1 from public.profiles p
      where p.id = auth.uid() and p.is_admin = true
    )
  );

-- (Optional) Only admins can delete items.
create policy "Items: admin delete all"
  on public.items for delete to authenticated
  using (
    exists (
      select 1 from public.profiles p
      where p.id = auth.uid() and p.is_admin = true
    )
  );

/* CLAIMS policies */
-- Students can see their own claims; admins can see all claims.
create policy "Claims: select own or admin"
  on public.claims for select to authenticated
  using (
    claimer_id = auth.uid()
    or exists (
      select 1 from public.profiles p
      where p.id = auth.uid() and p.is_admin = true
    )
  );

-- Students can create claims for themselves.
create policy "Claims: insert own"
  on public.claims for insert to authenticated
  with check (claimer_id = auth.uid());

-- Students may cancel (delete) their own pending claim; admins can delete any.
create policy "Claims: delete own pending or admin"
  on public.claims for delete to authenticated
  using (
    (claimer_id = auth.uid() and status = 'pending')
    or exists (
      select 1 from public.profiles p
      where p.id = auth.uid() and p.is_admin = true
    )
  );

-- Only admins can update claim status (approve/deny).
create policy "Claims: admin update all"
  on public.claims for update to authenticated
  using (
    exists (
      select 1 from public.profiles p
      where p.id = auth.uid() and p.is_admin = true
    )
  );
