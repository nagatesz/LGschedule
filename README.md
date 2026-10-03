# LGschedule (multi-user)

## Deploy
1. Supabase: create a project, run `supabase.sql` in the SQL editor (if you already ran the old one, run the commented `alter table` line too).
2. Google Cloud: create an OAuth "Web" client; add your Vercel domain to Authorized JavaScript origins.
3. Vercel env vars: `SUPABASE_URL`, `SUPABASE_SERVICE_KEY` (service_role key, never in the browser), `GOOGLE_CLIENT_ID`, `SESSION_SECRET` (random 32+ chars), `ENC_KEY` (random 32+ chars, do not change later or saved tokens become unreadable), `ADMIN_EMAILS` (comma list), optional `ALLOWED_DOMAIN` (default lkgeorge.org, empty = any Google account).
4. Deploy. Sign in, import your token, copy your script.

## Notes
- Old widgets pointing at `/api/schedule` stop working; regenerate your script from your dashboard.
- Remove the hardcoded Flex token from the old repo's `api/index.py` (git history keeps it, so keep the token rotated).
- Schedule data is only cached in memory for 30s; logs older than ~24h are pruned.
