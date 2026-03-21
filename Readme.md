# oyenino-admin

Data owner + admin dashboard for oyenino.com form submissions.

## Architecture

```
oyenino-forms worker (existing)
  └─ service binding ──→ oyenino-admin worker
                              ├─ /api/ingest (internal, writes to D1)
                              └─ /admin/* (dashboard, reads from D1)
```

## Setup

```bash
# 1. Create D1 database
npm run db:create
# → paste database_id into wrangler.toml

# 2. Run schema
npm run db:migrate

# 3. Set admin password (used for login + cookie signing)
wrangler secret put ADMIN_KEY

# 4. Deploy
npm run deploy
```

## GitHub Actions

Add these secrets to the repo:
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

Auto-deploys on push to `main`.

## Access

Visit the worker URL `/admin` → enter admin key → dashboard.