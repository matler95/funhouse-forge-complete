revoke execute on function public.is_member(uuid, uuid) from public, anon;
revoke execute on function public.has_org_role(uuid, uuid, text) from public, anon;
revoke execute on function public.shares_org(uuid, uuid) from public, anon;
revoke execute on function public.handle_new_user() from public, anon, authenticated;
grant execute on function public.is_member(uuid, uuid) to authenticated;
grant execute on function public.has_org_role(uuid, uuid, text) to authenticated;
grant execute on function public.shares_org(uuid, uuid) to authenticated;