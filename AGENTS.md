<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## Architecture rules
- File bytes live in a private `files` bucket accessed only via server-issued signed URLs (upload links are write-only; no storage RLS policies) — keeps anonymous senders from ever reading.
- External services (Web Push, e-mail invites, antivirus) are dummies writing to `notifications_outbox`/console — POC runs without third-party accounts.
