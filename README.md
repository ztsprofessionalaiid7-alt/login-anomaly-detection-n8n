# Brute-Force & Anomalous Login Detection (n8n)

An n8n workflow that analyses login logs for brute-force and credential-stuffing patterns, lets Gemini decide the response, alerts Slack, optionally blocks the IP on Cloudflare and logs every decision to Postgres.

▶ **Demo video:** https://drive.google.com/file/d/136SL-Irv4QLNgvkdXnFag4p7R1hUHfY2/view

## How it works

1. Mock login logs are grouped per IP (failed count, distinct usernames, success after failures)
2. A rule check decides if a pattern needs AI review
3. Gemini returns a decision (action and reason) as structured JSON
4. A Switch routes by action:
   - Block: Cloudflare Block IP, Slack alert, database log
   - Alert or monitor: Slack alert, database log
5. Every decision is stored in Supabase Postgres

```
Manual Trigger -> Mock Logs -> Analyze Logins -> Needs AI?
-> Analyze Pattern (Gemini + Output Parser) -> Parse AI Decision -> Switch
Switch -> Cloudflare Block IP -> Slack Alert -> Log Decision
```

## Tech stack

n8n Cloud, Google Gemini, Slack, Cloudflare API (optional), Supabase (Postgres)

## Setup

1. Import `login-detection-cloud.json` into n8n
2. Create credentials: Google Gemini, Slack, Postgres (Supabase Session pooler, SSL: Require)
3. Slack node: channel `security-alerts`, invite the bot to it
4. Create the database table (below)
5. Click **Execute workflow**: mock logs run through all branches

## Cloudflare Block IP (optional)

The node is **disabled by default**. Test the full flow first, then enable it:

- Method: POST
- URL: `https://api.cloudflare.com/client/v4/accounts/YOUR_ACCOUNT_ID/firewall/access_rules/rules`
- Credential: Header Auth, name `Authorization`, value `Bearer YOUR_TOKEN`

## Database

```sql
create table if not exists public.login_decisions (
  id bigint generated always as identity primary key,
  ip text,
  failed_count integer,
  distinct_users integer,
  action text,
  reason text,
  created_at timestamptz default now()
);
```

## Notes

- Always test blocking with mock data before enabling Cloudflare on real traffic
- Never commit API keys. Use n8n credentials only

## Author

Zarin Tasnim Shaily, AI Automation Engineer
[LinkedIn](https://linkedin.com/in/5ha1l72) | [GitHub](https://github.com/ztsprofessionalaiid7-alt)
