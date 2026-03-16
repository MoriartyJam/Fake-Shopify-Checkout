# Fake Shopify Checkout Backend

Flask backend for Shopify OAuth install flow and draft order creation.

## Setup

1. Create and activate venv.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Configure environment variables in your server/panel (no `.env` file required).

4. Run:

```bash
python app.py
```

## Required Environment Variables

- `CLIENT_ID`
- `API_SECRET`
- `APP_URL`
- `TOKEN_ENCRYPTION_KEY`

## Shopify App Settings

- App URL: `https://your-domain`
- Redirect URL: `https://your-domain/auth/callback`
- Webhook URL (`app/uninstalled`): `https://your-domain/webhooks/app-uninstalled`
