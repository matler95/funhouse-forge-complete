create table public.invitations (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations(id) on delete cascade,
  email text not null check (char_length(email) between 3 and 255),
  role text not null default 'doctor' check (role in ('admin','doctor','staff')),
  invited_by uuid not null,
  accepted_at timestamptz,
  declined_at timestamptz,
  created_at timestamptz not null default now()
);
create unique index invitations_pending_uniq on public.invitations (org_id, lower(email)) where accepted_at is null and declined_at is null;
grant select, delete on public.invitations to authenticated;
grant all on public.invitations to service_role;
alter table public.invitations enable row level security;
create policy "inv read" on public.invitations for select to authenticated using (public.has_org_role(org_id, auth.uid(), 'admin') or lower(email) = lower(auth.jwt()->>'email'));
create policy "inv admin delete" on public.invitations for delete to authenticated using (public.has_org_role(org_id, auth.uid(), 'admin'));

create or replace function public.respond_invitation(_id uuid, _accept boolean) returns uuid
language plpgsql security definer set search_path = public as $$
declare inv public.invitations;
begin
  if auth.uid() is null then raise exception 'not authenticated'; end if;
  select * into inv from public.invitations where id = _id and accepted_at is null and declined_at is null;
  if inv.id is null or lower(inv.email) <> lower(auth.jwt()->>'email') then raise exception 'invitation not found'; end if;
  if _accept then
    insert into public.memberships(org_id, user_id, role) values (inv.org_id, auth.uid(), inv.role)
      on conflict (org_id, user_id) do nothing;
    update public.invitations set accepted_at = now() where id = _id;
    insert into public.audit_log(org_id, actor_user_id, action, target) values (inv.org_id, auth.uid(), 'invite.accept', inv.email);
  else
    update public.invitations set declined_at = now() where id = _id;
    insert into public.audit_log(org_id, actor_user_id, action, target) values (inv.org_id, auth.uid(), 'invite.decline', inv.email);
  end if;
  return inv.org_id;
end $$;

create or replace function public.set_member_role(_membership uuid, _role text) returns void
language plpgsql security definer set search_path = public as $$
declare m public.memberships; admins int;
begin
  if _role not in ('admin','doctor','staff') then raise exception 'bad role'; end if;
  select * into m from public.memberships where id = _membership;
  if m.id is null or not public.has_org_role(m.org_id, auth.uid(), 'admin') then raise exception 'forbidden'; end if;
  if m.role = 'admin' and _role <> 'admin' then
    select count(*) into admins from public.memberships where org_id = m.org_id and role = 'admin';
    if admins <= 1 then raise exception 'last admin'; end if;
  end if;
  update public.memberships set role = _role where id = _membership;
  insert into public.audit_log(org_id, actor_user_id, action, target) values (m.org_id, auth.uid(), 'member.role', _role);
end $$;

create or replace function public.leave_organization(_org uuid) returns void
language plpgsql security definer set search_path = public as $$
declare m public.memberships; admins int; k text;
begin
  select kind into k from public.organizations where id = _org;
  if k = 'personal' then raise exception 'personal'; end if;
  select * into m from public.memberships where org_id = _org and user_id = auth.uid();
  if m.id is null then raise exception 'not member'; end if;
  if m.role = 'admin' then
    select count(*) into admins from public.memberships where org_id = _org and role = 'admin';
    if admins <= 1 and (select count(*) from public.memberships where org_id = _org) > 1 then raise exception 'last admin'; end if;
  end if;
  delete from public.memberships where id = m.id;
  update public.drop_links set revoked_at = now() where org_id = _org and recipient_user_id = auth.uid() and revoked_at is null;
  insert into public.audit_log(org_id, actor_user_id, action, target) values (_org, auth.uid(), 'member.leave', null);
end $$;

revoke execute on function public.respond_invitation(uuid, boolean) from public, anon;
revoke execute on function public.set_member_role(uuid, text) from public, anon;
revoke execute on function public.leave_organization(uuid) from public, anon;
grant execute on function public.respond_invitation(uuid, boolean) to authenticated;
grant execute on function public.set_member_role(uuid, text) to authenticated;
grant execute on function public.leave_organization(uuid) to authenticated;