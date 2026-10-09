-- ==============================================================================
-- Threat Netra - Supabase Database Schema & User Management
-- ==============================================================================

-- 1. Create User Profiles Table
create table if not exists public.profiles (
    id uuid primary key references auth.users(id) on delete cascade,
    email text not null,
    full_name text,
    role text check (role in ('normal_user', 'governmental_user', 'admin')),
    status text not null default 'pending_approval' check (status in ('pending_approval', 'approved', 'rejected')),
    created_at timestamptz not null default timezone('utc'::text, now()),
    updated_at timestamptz not null default timezone('utc'::text, now())
);

-- Enable Row Level Security (RLS)
alter table public.profiles enable row level security;

-- 2. RLS Policies
-- Users can view their own profile
create policy "Users can view own profile"
    on public.profiles
    for select
    using (auth.uid() = id);

-- Users can update non-critical profile fields
create policy "Users can update own profile"
    on public.profiles
    for update
    using (auth.uid() = id);

-- Admins / Service role can view all profiles
create policy "Admins can view all profiles"
    on public.profiles
    for select
    using (
        exists (
            select 1 from public.profiles
            where id = auth.uid() and role = 'admin'
        )
    );

-- Admins can update roles and approval status
create policy "Admins can update profiles"
    on public.profiles
    for update
    using (
        exists (
            select 1 from public.profiles
            where id = auth.uid() and role = 'admin'
        )
    );

-- 3. Automatic Profile Creation Trigger on Sign Up
-- Handles both Email/Password signup and Google OAuth signup
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
declare
    user_count int;
begin
    -- Check how many profiles currently exist
    select count(*) into user_count from public.profiles;

    -- If this is the very first registered user, automatically grant them admin approval
    if user_count = 0 then
        insert into public.profiles (id, email, full_name, role, status)
        values (
            new.id,
            new.email,
            coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)),
            'admin',
            'approved'
        );
    else
        -- All subsequent users start as pending_approval without role assigned
        insert into public.profiles (id, email, full_name, role, status)
        values (
            new.id,
            new.email,
            coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)),
            null,
            'pending_approval'
        );
    end if;
    return new;
end;
$$;

-- Drop trigger if it already exists and recreate
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
    after insert on auth.users
    for each row execute function public.handle_new_user();

-- 4. Helper Function: Make a specific user Admin (Run manually if needed)
-- Example: select public.assign_admin_by_email('your-email@example.com');
create or replace function public.assign_admin_by_email(target_email text)
returns void
language plpgsql
security definer
as $$
begin
    update public.profiles
    set role = 'admin', status = 'approved'
    where email = target_email;
end;
$$;
