# Setup checklist
## Supabase
1. supabase.com -> New project (any name/region). Wait until it finishes starting.
2. SQL Editor -> New query -> paste supabase.sql -> Run. Table Editor should now show `users` and `logs`.
3. Project Settings -> API: copy the Project URL (https://xxxx.supabase.co) -> SUPABASE_URL.
4. Same page: copy the `service_role` key (or the new "secret" key, sb_secret_...) -> SUPABASE_SERVICE_KEY. NOT the anon/publishable key. Never put it in the website code.
## Google
Google Cloud Console -> APIs & Services -> Credentials -> Create OAuth client ID (Web). Add your Vercel URL under Authorized JavaScript origins. Copy the Client ID -> GOOGLE_CLIENT_ID.
## Vercel (Settings -> Environment Variables, then Redeploy)
SUPABASE_URL, SUPABASE_SERVICE_KEY, GOOGLE_CLIENT_ID, SESSION_SECRET (random 32+ chars), ENC_KEY (random 32+ chars, never change it later), ADMIN_EMAILS (your email). Optional: DEBUG_LOGS=1.
## Verify
Sign in, import a token, then check Supabase Table Editor -> users: your row appears. Open /admin.html -> System check should say Database OK.
