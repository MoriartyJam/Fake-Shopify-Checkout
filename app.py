import os
import json
import logging
import secrets
import hmac
import hashlib
import base64
import sqlite3
import re
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from flask import Flask, request, jsonify, redirect, render_template_string
from flask_cors import CORS
import requests
import shopify
from cryptography.fernet import Fernet, InvalidToken

# Настройка Flask
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "https://mixopro.store",
            "https://www.mixopro.store",
            r"^https://[a-z0-9-]+\.myshopify\.com$",
            r"^https://[a-z0-9-]+\.shopifypreview\.com$",
            r"^https://admin\.shopify\.com$"
        ],
        "methods": ["POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})

# Настройка расширенного логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)
LOG_BUFFER = deque(maxlen=400)


class InMemoryLogHandler(logging.Handler):
    def emit(self, record):
        try:
            LOG_BUFFER.append(self.format(record))
        except Exception:
            pass


memory_handler = InMemoryLogHandler()
memory_handler.setLevel(logging.INFO)
memory_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
logger.addHandler(memory_handler)

# Shopify app credentials (set as server environment variables)
SHOPIFY_CLIENT_ID = os.getenv("CLIENT_ID", "")
SHOPIFY_API_SECRET = os.getenv("API_SECRET", "")
SHOPIFY_SCOPES = os.getenv(
    "SCOPES",
    "read_products,write_products,write_inventory,read_metaobjects,write_metaobjects,read_metaobject_definitions,write_metaobject_definitions"
)
SHOP_URL = os.getenv("SHOP_URL", "")
APP_URL = os.getenv("APP_URL", "")
REDIRECT_URI = f"{APP_URL}/auth/callback" if APP_URL else ""
SCOPES = [scope.strip() for scope in SHOPIFY_SCOPES.split(",") if scope.strip()]
API_VERSION = os.getenv('API_VERSION', '2026-01')
PORT = int(os.getenv('PORT', 80))
SHOPIFY_ACCESS_TOKEN = os.getenv("SHOPIFY_ACCESS_TOKEN", "")
TOKEN_DB_PATH = os.getenv("TOKEN_DB_PATH", "shop_tokens.db")
DATABASE_URL = os.getenv("DATABASE_URL", "")
TOKEN_ENCRYPTION_KEY = os.getenv("TOKEN_ENCRYPTION_KEY", "")
ENCRYPTED_TOKEN_PREFIX = "enc:"
EXIT_SURVEY_METAOBJECT_TYPE = "exit_survey_response"
EXIT_SURVEY_RATE_LIMIT = int(os.getenv("EXIT_SURVEY_RATE_LIMIT", "20"))
EXIT_SURVEY_RATE_WINDOW_SECONDS = int(os.getenv("EXIT_SURVEY_RATE_WINDOW_SECONDS", "3600"))
EXIT_SURVEY_REQUESTS = {}
COMPETITOR_CRON_SECRET = os.getenv("COMPETITOR_CRON_SECRET", "")
COMPETITOR_TAG = "competitor-price-compare"
COMPETITOR_NAMESPACE = "price_comparison"
COMPETITOR_TIMEOUT_SECONDS = int(os.getenv("COMPETITOR_TIMEOUT_SECONDS", "15"))
COMPETITOR_USER_AGENT = os.getenv(
    "COMPETITOR_USER_AGENT",
    "MIXOproPriceMonitor/1.0 (+https://mixopro.store)"
)
COMPETITOR_SOURCES = {
    "monin_url": {
        "name": "MONIN.ca",
        "hosts": {"monin.ca", "www.monin.ca"}
    },
    "cocktail_emporium_url": {
        "name": "Cocktail Emporium",
        "hosts": {"cocktailemporium.com", "www.cocktailemporium.com"}
    },
    "kitchen_barista_url": {
        "name": "The Kitchen Barista",
        "hosts": {"thekitchenbarista.com", "www.thekitchenbarista.com"}
    },
    "ecs_coffee_url": {
        "name": "ECS Coffee",
        "hosts": {"ecscoffee.com", "www.ecscoffee.com"}
    },
    "mayrand_url": {
        "name": "Mayrand",
        "hosts": {"mayrand.ca", "www.mayrand.ca"}
    }
}

fernet = None
if TOKEN_ENCRYPTION_KEY:
    try:
        fernet = Fernet(TOKEN_ENCRYPTION_KEY.encode("utf-8"))
    except Exception as e:
        logger.error(f"❌ Invalid TOKEN_ENCRYPTION_KEY: {e}")
else:
    logger.warning("⚠️ TOKEN_ENCRYPTION_KEY не задан. Токены в БД не будут шифроваться.")


def use_postgres():
    return DATABASE_URL.startswith("postgresql://") or DATABASE_URL.startswith("postgres://")


def get_db_connection():
    if use_postgres():
        import psycopg2
        return psycopg2.connect(DATABASE_URL)
    conn = sqlite3.connect(TOKEN_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_token_db():
    with get_db_connection() as conn:
        if use_postgres():
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS shop_tokens (
                        shop_domain TEXT PRIMARY KEY,
                        access_token TEXT NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                    """
                )
            conn.commit()
        else:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS shop_tokens (
                    shop_domain TEXT PRIMARY KEY,
                    access_token TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.commit()


def encrypt_token(access_token):
    if not fernet:
        return access_token
    encrypted = fernet.encrypt(access_token.encode("utf-8")).decode("utf-8")
    return f"{ENCRYPTED_TOKEN_PREFIX}{encrypted}"


def decrypt_token(stored_token):
    if not stored_token:
        return None
    if not stored_token.startswith(ENCRYPTED_TOKEN_PREFIX):
        # Backward compatibility for legacy plaintext rows.
        return stored_token
    if not fernet:
        raise ValueError("TOKEN_ENCRYPTION_KEY is required to decrypt tokens.")
    encrypted = stored_token[len(ENCRYPTED_TOKEN_PREFIX):]
    try:
        return fernet.decrypt(encrypted.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        raise ValueError("Failed to decrypt token with current TOKEN_ENCRYPTION_KEY.")


def get_shop_token(shop_domain):
    with get_db_connection() as conn:
        if use_postgres():
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT access_token FROM shop_tokens WHERE shop_domain = %s",
                    (shop_domain,)
                )
                row = cur.fetchone()
                return decrypt_token(row[0]) if row else None
        row = conn.execute(
            "SELECT access_token FROM shop_tokens WHERE shop_domain = ?",
            (shop_domain,)
        ).fetchone()
        return decrypt_token(row["access_token"]) if row else None


def save_shop_token(shop_domain, access_token):
    token_to_store = encrypt_token(access_token)
    with get_db_connection() as conn:
        if use_postgres():
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO shop_tokens (shop_domain, access_token, updated_at)
                    VALUES (%s, %s, NOW())
                    ON CONFLICT(shop_domain) DO UPDATE SET
                        access_token = EXCLUDED.access_token,
                        updated_at = NOW()
                    """,
                    (shop_domain, token_to_store)
                )
        else:
            conn.execute(
                """
                INSERT INTO shop_tokens (shop_domain, access_token, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(shop_domain) DO UPDATE SET
                    access_token = excluded.access_token,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (shop_domain, token_to_store)
            )
        conn.commit()


def delete_shop_token(shop_domain):
    with get_db_connection() as conn:
        if use_postgres():
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM shop_tokens WHERE shop_domain = %s",
                    (shop_domain,)
                )
        else:
            conn.execute(
                "DELETE FROM shop_tokens WHERE shop_domain = ?",
                (shop_domain,)
            )
        conn.commit()


def list_installed_shops():
    with get_db_connection() as conn:
        if use_postgres():
            with conn.cursor() as cur:
                cur.execute("SELECT shop_domain FROM shop_tokens ORDER BY shop_domain")
                rows = cur.fetchall()
                return [row[0] for row in rows]
        rows = conn.execute(
            "SELECT shop_domain FROM shop_tokens ORDER BY shop_domain"
        ).fetchall()
        return [row["shop_domain"] for row in rows]

if not SHOPIFY_CLIENT_ID or not SHOPIFY_API_SECRET:
    logger.warning("⚠️ CLIENT_ID или API_SECRET не заданы. OAuth endpoints не будут работать.")

# Required for OAuth token exchange
shopify.Session.setup(api_key=SHOPIFY_CLIENT_ID, secret=SHOPIFY_API_SECRET)
init_token_db()
logger.info(f"🗄️ Token DB backend: {'PostgreSQL' if use_postgres() else 'SQLite'}")

# Optional bootstrap token (single-shop fallback)
if SHOPIFY_ACCESS_TOKEN and SHOP_URL and not get_shop_token(SHOP_URL):
    save_shop_token(SHOP_URL, SHOPIFY_ACCESS_TOKEN)


def activate_shop_session(shop_domain):
    token = get_shop_token(shop_domain)
    resolved_shop = shop_domain

    # Single-shop fallback: if request shop has no token, reuse configured SHOP_URL token.
    if not token and SHOP_URL and shop_domain != SHOP_URL:
        fallback_token = get_shop_token(SHOP_URL)
        if fallback_token:
            logger.warning(
                f"⚠️ No token for requested shop={shop_domain}. "
                f"Using fallback token for SHOP_URL={SHOP_URL}."
            )
            token = fallback_token
            resolved_shop = SHOP_URL

    # Environment-token fallback for single-shop deployments with empty/ephemeral DB.
    if not token and SHOPIFY_ACCESS_TOKEN:
        resolved_shop = SHOP_URL or shop_domain
        token = SHOPIFY_ACCESS_TOKEN
        logger.warning(
            f"⚠️ No DB token for shop={shop_domain}. "
            f"Using SHOPIFY_ACCESS_TOKEN for resolved_shop={resolved_shop}."
        )

    if not token:
        raise ValueError(f"No access token for shop: {shop_domain}. Install app via /auth first.")

    session = shopify.Session(resolved_shop, API_VERSION, token)
    shopify.ShopifyResource.activate_session(session)
    return resolved_shop


def validate_hmac(query_params):
    params = dict(query_params)
    received_hmac = params.pop("hmac", None)
    if not received_hmac:
        return False
    message = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    digest = hmac.new(
        SHOPIFY_API_SECRET.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(digest, received_hmac)


def verify_webhook_hmac(raw_data, hmac_header):
    if not SHOPIFY_API_SECRET or not hmac_header:
        return False
    digest = hmac.new(
        SHOPIFY_API_SECRET.encode("utf-8"),
        raw_data,
        hashlib.sha256
    ).digest()
    calculated = base64.b64encode(digest).decode("utf-8")
    return hmac.compare_digest(calculated, hmac_header)


def mask_email(email):
    if not email or "@" not in email:
        return "N/A"
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        return f"{local[0]}***@{domain}"
    return f"{local[:2]}***@{domain}"


def mask_phone(phone):
    if not phone:
        return "N/A"
    digits = "".join(ch for ch in str(phone) if ch.isdigit())
    if len(digits) <= 4:
        return "***"
    return f"***{digits[-4:]}"


def mask_text(value, keep=3):
    if not value:
        return "N/A"
    value = str(value)
    if len(value) <= keep:
        return "*" * len(value)
    return f"{value[:keep]}***"


def log_request_data(data):
    """Логирование входящих данных"""
    logger.info("=" * 80)
    logger.info("📥 ПОЛУЧЕН ЗАПРОС НА СОЗДАНИЕ DRAFT ORDER")
    logger.info("=" * 80)
    logger.info(f"📧 Email: {mask_email(data.get('email'))}")
    logger.info(f"👤 Имя: {mask_text(data.get('customer', {}).get('first_name', ''))} {mask_text(data.get('customer', {}).get('last_name', ''))}")
    logger.info(f"🏢 Компания: {mask_text(data.get('customer', {}).get('company', ''))}")
    logger.info(f"📞 Телефон: {mask_phone(data.get('customer', {}).get('phone'))}")
    logger.info(f"📦 Количество товаров: {len(data.get('line_items', []))}")
    logger.info(f"📝 Заметка: {data.get('note', 'Нет заметок')}")
    logger.info("-" * 80)


def log_line_items(line_items):
    """Логирование товаров в заказе"""
    logger.info("🛒 ТОВАРЫ В ЗАКАЗЕ:")
    for idx, item in enumerate(line_items, 1):
        logger.info(f"  {idx}. {item.get('title', 'N/A')}")
        logger.info(f"     - Variant ID: {item.get('variant_id', 'N/A')}")
        logger.info(f"     - Количество: {item.get('quantity', 0)}")
        logger.info(f"     - Цена: ${item.get('price', 0) / 100:.2f}")
    logger.info("-" * 80)


def log_shipping_address(address):
    """Логирование адреса доставки"""
    logger.info("📍 АДРЕС ДОСТАВКИ:")
    logger.info(f"  Улица: {mask_text(address.get('address1', ''))}")
    if address.get('address2'):
        logger.info(f"  Квартира: {mask_text(address.get('address2', ''))}")
    logger.info(f"  Город: {mask_text(address.get('city', ''))}")
    logger.info(f"  Провинция: {mask_text(address.get('province', ''))}")
    logger.info(f"  Страна: {address.get('country', 'N/A')}")
    logger.info(f"  Индекс: {mask_text(address.get('zip', ''), keep=2)}")
    logger.info("-" * 80)


def log_exit_customer_request(data):
    logger.info("=" * 80)
    logger.info("📥 ПОЛУЧЕН ЗАПРОС НА СОЗДАНИЕ CUSTOMER ИЗ EXIT POPUP")
    logger.info("=" * 80)
    logger.info(f"👤 Имя: {mask_text(data.get('customer', {}).get('first_name', ''))}")
    logger.info(f"📞 Телефон: {mask_phone(data.get('customer', {}).get('phone'))}")
    logger.info(f"🏷️ Тег: {data.get('tag', 'exit')}")
    logger.info("-" * 80)


def get_variant_stock_snapshot(variant_id):
    """Возвращает остаток как в админке Shopify: total available across all locations."""
    try:
        variant = shopify.Variant.find(variant_id)
        inventory_management = getattr(variant, "inventory_management", None)
        tracked = bool(inventory_management)
        available_qty = getattr(variant, "inventory_quantity", None) if tracked else None
        return {
            "tracked": tracked,
            "available_qty": available_qty
        }
    except Exception as e:
        logger.warning(f"⚠️ Не удалось получить остаток для variant_id={variant_id}: {str(e)}")
        return {
            "tracked": False,
            "available_qty": None
        }


def execute_shopify_graphql(query, variables=None):
    """Execute Admin GraphQL using the currently active Shopify session."""
    raw_response = shopify.GraphQL().execute(query, variables=variables or {})
    response = json.loads(raw_response)
    if response.get("errors"):
        raise RuntimeError(f"Shopify GraphQL errors: {response['errors']}")
    return response.get("data") or {}


def ensure_exit_survey_definition():
    """Create the merchant-visible Metaobject definition once, if necessary."""
    lookup_query = """
    query ExitSurveyDefinition($type: String!) {
      metaobjectDefinitionByType(type: $type) {
        id
        type
      }
    }
    """
    lookup = execute_shopify_graphql(
        lookup_query,
        {"type": EXIT_SURVEY_METAOBJECT_TYPE}
    )
    existing = lookup.get("metaobjectDefinitionByType")
    if existing:
        return existing["id"]

    create_mutation = """
    mutation CreateExitSurveyDefinition($definition: MetaobjectDefinitionCreateInput!) {
      metaobjectDefinitionCreate(definition: $definition) {
        metaobjectDefinition {
          id
          type
        }
        userErrors {
          field
          message
          code
        }
      }
    }
    """
    definition = {
        "name": "Exit survey response",
        "type": EXIT_SURVEY_METAOBJECT_TYPE,
        "description": "Anonymous feedback collected by the MIXOpro exit-intent popup.",
        "displayNameKey": "reason",
        "fieldDefinitions": [
            {"name": "Reason", "key": "reason", "type": "single_line_text_field", "required": True},
            {"name": "Comment", "key": "comment", "type": "multi_line_text_field"},
            {"name": "Page URL", "key": "page_url", "type": "url"},
            {"name": "Page title", "key": "page_title", "type": "single_line_text_field"},
            {"name": "Locale", "key": "locale", "type": "single_line_text_field"},
            {"name": "Trigger", "key": "trigger", "type": "single_line_text_field"},
            {"name": "Source", "key": "source", "type": "single_line_text_field"},
            {"name": "Submitted at", "key": "submitted_at", "type": "date_time", "required": True}
        ]
    }
    created = execute_shopify_graphql(
        create_mutation,
        {"definition": definition}
    ).get("metaobjectDefinitionCreate") or {}
    user_errors = created.get("userErrors") or []
    if user_errors:
        # Another request might have created it between lookup and mutation.
        repeated_lookup = execute_shopify_graphql(
            lookup_query,
            {"type": EXIT_SURVEY_METAOBJECT_TYPE}
        ).get("metaobjectDefinitionByType")
        if repeated_lookup:
            return repeated_lookup["id"]
        raise ValueError(f"Metaobject definition errors: {user_errors}")

    metaobject_definition = created.get("metaobjectDefinition")
    if not metaobject_definition:
        raise RuntimeError("Shopify did not return the created Metaobject definition.")
    return metaobject_definition["id"]


def create_exit_survey_metaobject(payload):
    ensure_exit_survey_definition()
    create_mutation = """
    mutation CreateExitSurveyResponse($metaobject: MetaobjectCreateInput!) {
      metaobjectCreate(metaobject: $metaobject) {
        metaobject {
          id
          handle
          displayName
        }
        userErrors {
          field
          message
          code
        }
      }
    }
    """
    handle = f"exit-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(4)}"
    fields = [
        {"key": "reason", "value": payload["reason"]},
        {"key": "comment", "value": payload.get("comment", "")},
        {"key": "page_url", "value": payload.get("page_url", "")},
        {"key": "page_title", "value": payload.get("page_title", "")},
        {"key": "locale", "value": payload.get("locale", "")},
        {"key": "trigger", "value": payload.get("trigger", "")},
        {"key": "source", "value": payload.get("source", "exit_intent_survey")},
        {"key": "submitted_at", "value": payload["submitted_at"]}
    ]
    result = execute_shopify_graphql(
        create_mutation,
        {
            "metaobject": {
                "type": EXIT_SURVEY_METAOBJECT_TYPE,
                "handle": handle,
                "fields": fields
            }
        }
    ).get("metaobjectCreate") or {}
    user_errors = result.get("userErrors") or []
    if user_errors:
        raise ValueError(f"Metaobject create errors: {user_errors}")
    metaobject = result.get("metaobject")
    if not metaobject:
        raise RuntimeError("Shopify did not return the created Metaobject.")
    return metaobject


def exit_survey_rate_limited():
    """Small in-process spam guard; use a shared rate limiter for multi-instance deploys."""
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    client_ip = forwarded_for.split(",", 1)[0].strip() or request.remote_addr or "unknown"
    now = datetime.now().timestamp()
    recent = EXIT_SURVEY_REQUESTS.setdefault(client_ip, deque())
    while recent and now - recent[0] > EXIT_SURVEY_RATE_WINDOW_SECONDS:
        recent.popleft()
    if len(recent) >= EXIT_SURVEY_RATE_LIMIT:
        return True
    recent.append(now)
    return False


class JsonLdScriptParser(HTMLParser):
    """Collect JSON-LD script bodies without adding an HTML parser dependency."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._inside_json_ld = False
        self._buffer = []
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "script":
            return
        attributes = {key.lower(): (value or "") for key, value in attrs}
        self._inside_json_ld = "ld+json" in attributes.get("type", "").lower()
        self._buffer = []

    def handle_data(self, data):
        if self._inside_json_ld:
            self._buffer.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._inside_json_ld:
            self.scripts.append("".join(self._buffer).strip())
            self._inside_json_ld = False
            self._buffer = []


def competitor_request_is_authorized():
    if not COMPETITOR_CRON_SECRET:
        return False
    authorization = request.headers.get("Authorization", "")
    supplied = request.headers.get("X-Cron-Secret", "")
    if authorization.startswith("Bearer "):
        supplied = authorization[7:]
    return hmac.compare_digest(str(supplied), COMPETITOR_CRON_SECRET)


def ensure_competitor_metafield_definitions():
    """Create pinned URL fields and unpinned parser-owned output fields."""
    definitions = []
    for key, source in COMPETITOR_SOURCES.items():
        definitions.append({
            "name": f"{source['name']} product URL",
            "namespace": COMPETITOR_NAMESPACE,
            "key": key,
            "description": f"Paste the matching {source['name']} product or variant URL. Price is updated automatically.",
            "type": "url",
            "ownerType": "PRODUCT",
            "pin": True
        })
    definitions.extend([
        {
            "name": "Competitor price results",
            "namespace": COMPETITOR_NAMESPACE,
            "key": "results",
            "description": "Managed automatically by the MIXOpro competitor price monitor.",
            "type": "json",
            "ownerType": "PRODUCT",
            "pin": False
        },
        {
            "name": "Competitor prices checked at",
            "namespace": COMPETITOR_NAMESPACE,
            "key": "last_checked_at",
            "description": "Last automatic competitor price check.",
            "type": "date_time",
            "ownerType": "PRODUCT",
            "pin": False
        }
    ])

    mutation = """
    mutation CreateCompetitorMetafieldDefinition($definition: MetafieldDefinitionInput!) {
      metafieldDefinitionCreate(definition: $definition) {
        createdDefinition { id name namespace key }
        userErrors { field message code }
      }
    }
    """
    created = []
    existing = []
    for definition in definitions:
        payload = execute_shopify_graphql(mutation, {"definition": definition}).get(
            "metafieldDefinitionCreate"
        ) or {}
        errors = payload.get("userErrors") or []
        if errors:
            if all(error.get("code") == "TAKEN" for error in errors):
                existing.append(definition["key"])
                continue
            raise ValueError(f"Metafield definition errors for {definition['key']}: {errors}")
        created.append(definition["key"])
    return {"created": created, "existing": existing}


def clean_competitor_url(raw_url, source_key):
    source = COMPETITOR_SOURCES[source_key]
    parsed = urlparse((raw_url or "").strip())
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or hostname not in source["hosts"]:
        raise ValueError(f"URL must use HTTPS and belong to {source['name']}")
    if "/products/" not in parsed.path:
        raise ValueError("URL must point to a product page")
    query = parse_qs(parsed.query, keep_blank_values=False)
    kept_query = {}
    for key in ("variant", "currency", "country"):
        if query.get(key):
            kept_query[key] = query[key][0]
    return urlunparse((
        "https",
        hostname,
        parsed.path.rstrip("/"),
        "",
        urlencode(kept_query),
        ""
    ))


def shopify_product_json_url(product_url):
    parsed = urlparse(product_url)
    path = re.sub(r"(/products/[^/?]+?)(?:\.js)?$", r"\1.js", parsed.path)
    return urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, ""))


def parse_money_value(value):
    if value is None or isinstance(value, bool):
        raise ValueError("Price is missing")
    if isinstance(value, (int, float)):
        return float(value)
    normalized = re.sub(r"[^0-9,.-]", "", str(value)).strip()
    if not normalized:
        raise ValueError("Price is missing")
    if "," in normalized and "." not in normalized:
        normalized = normalized.replace(",", ".")
    elif "," in normalized and "." in normalized:
        normalized = normalized.replace(",", "")
    return float(normalized)


def parse_shopify_product_json(response, product_url):
    data = response.json()
    variants = data.get("variants") or []
    query = parse_qs(urlparse(product_url).query)
    requested_variant = (query.get("variant") or [""])[0]
    variant = None
    if requested_variant:
        variant = next(
            (item for item in variants if str(item.get("id")) == str(requested_variant)),
            None
        )
        if not variant:
            raise ValueError(f"Variant {requested_variant} was not found")
    elif variants:
        variant = variants[0]

    price_raw = variant.get("price") if variant else data.get("price")
    price = parse_money_value(price_raw)
    # Shopify Ajax product JSON expresses money values in minor units.
    price /= 100
    currency = (
        data.get("currency")
        or (query.get("currency") or [""])[0]
        or "CAD"
    ).upper()
    available = variant.get("available") if variant else data.get("available", True)
    return {
        "price": round(price, 2),
        "currency": currency,
        "available": bool(available),
        "variant_id": str(variant.get("id")) if variant else "",
        "variant_title": str(variant.get("title") or "") if variant else "",
        "product_title": str(data.get("title") or ""),
        "parser": "shopify-product-json"
    }


def iter_json_objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from iter_json_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_json_objects(child)


def parse_product_json_ld(html):
    parser = JsonLdScriptParser()
    parser.feed(html)
    for script in parser.scripts:
        if not script:
            continue
        try:
            document = json.loads(script)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        for item in iter_json_objects(document):
            item_type = item.get("@type")
            types = item_type if isinstance(item_type, list) else [item_type]
            if "Product" not in types:
                continue
            offers = item.get("offers")
            if isinstance(offers, list):
                offers = offers[0] if offers else None
            if not isinstance(offers, dict):
                continue
            price_raw = offers.get("price") or offers.get("lowPrice")
            if price_raw is None:
                price_specification = offers.get("priceSpecification") or {}
                if isinstance(price_specification, list):
                    price_specification = price_specification[0] if price_specification else {}
                price_raw = price_specification.get("price")
            if price_raw is None:
                continue
            availability = str(offers.get("availability") or "")
            return {
                "price": round(parse_money_value(price_raw), 2),
                "currency": str(offers.get("priceCurrency") or "CAD").upper(),
                "available": "OutOfStock" not in availability and "SoldOut" not in availability,
                "variant_id": "",
                "variant_title": "",
                "product_title": str(item.get("name") or ""),
                "parser": "json-ld"
            }
    raise ValueError("No product offer with a price was found")


def fetch_competitor_price(source_key, raw_url):
    source = COMPETITOR_SOURCES[source_key]
    cleaned_url = clean_competitor_url(raw_url, source_key)
    headers = {
        "User-Agent": COMPETITOR_USER_AGENT,
        "Accept": "application/json,text/html;q=0.9,*/*;q=0.8"
    }
    checked_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    json_error = None
    try:
        response = requests.get(
            shopify_product_json_url(cleaned_url),
            headers=headers,
            timeout=COMPETITOR_TIMEOUT_SECONDS,
            allow_redirects=True
        )
        response.raise_for_status()
        parsed = parse_shopify_product_json(response, cleaned_url)
    except (requests.RequestException, ValueError, json.JSONDecodeError) as error:
        json_error = str(error)
        response = requests.get(
            cleaned_url,
            headers=headers,
            timeout=COMPETITOR_TIMEOUT_SECONDS,
            allow_redirects=True
        )
        response.raise_for_status()
        parsed = parse_product_json_ld(response.text)

    parsed.update({
        "key": source_key,
        "name": source["name"],
        "url": cleaned_url,
        "price_cents": int(round(parsed["price"] * 100)),
        "status": "ok" if parsed.get("available") else "unavailable",
        "checked_at": checked_at
    })
    if json_error and parsed.get("parser") == "json-ld":
        parsed["fallback_reason"] = json_error[:240]
    return parsed


def get_competitor_products():
    metafield_lines = "\n".join(
        f'{key}: metafield(namespace: "{COMPETITOR_NAMESPACE}", key: "{key}") {{ value }}'
        for key in COMPETITOR_SOURCES
    )
    query = """
    query CompetitorProducts($after: String) {
      products(first: 50, after: $after, query: "tag:%s") {
        pageInfo { hasNextPage endCursor }
        nodes {
          id
          title
          handle
          %s
        }
      }
    }
    """ % (COMPETITOR_TAG, metafield_lines)
    products = []
    after = None
    while True:
        connection = execute_shopify_graphql(query, {"after": after}).get("products") or {}
        products.extend(connection.get("nodes") or [])
        page_info = connection.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            return products
        after = page_info.get("endCursor")


def save_competitor_results(product_id, results, checked_at):
    mutation = """
    mutation SaveCompetitorPrices($metafields: [MetafieldsSetInput!]!) {
      metafieldsSet(metafields: $metafields) {
        metafields { id key updatedAt }
        userErrors { field message code }
      }
    }
    """
    metafields = [
        {
            "ownerId": product_id,
            "namespace": COMPETITOR_NAMESPACE,
            "key": "results",
            "type": "json",
            "value": json.dumps(results, ensure_ascii=False, separators=(",", ":"))
        },
        {
            "ownerId": product_id,
            "namespace": COMPETITOR_NAMESPACE,
            "key": "last_checked_at",
            "type": "date_time",
            "value": checked_at
        }
    ]
    payload = execute_shopify_graphql(mutation, {"metafields": metafields}).get("metafieldsSet") or {}
    errors = payload.get("userErrors") or []
    if errors:
        raise ValueError(f"Metafield save errors: {errors}")


def refresh_competitor_prices():
    products = get_competitor_products()
    summary = {"products_found": len(products), "products_updated": 0, "sources_ok": 0, "sources_failed": 0, "products": []}
    for product in products:
        checked_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        results = []
        for source_key, source in COMPETITOR_SOURCES.items():
            metafield = product.get(source_key) or {}
            raw_url = metafield.get("value") or ""
            if not raw_url:
                continue
            try:
                result = fetch_competitor_price(source_key, raw_url)
                summary["sources_ok"] += 1
                logger.info(
                    f"💰 Competitor price: product={product['handle']}, source={source['name']}, "
                    f"price={result['price']} {result['currency']}"
                )
            except Exception as error:
                summary["sources_failed"] += 1
                result = {
                    "key": source_key,
                    "name": source["name"],
                    "url": raw_url,
                    "status": "error",
                    "error": str(error)[:300],
                    "checked_at": checked_at
                }
                logger.warning(
                    f"⚠️ Competitor price failed: product={product['handle']}, "
                    f"source={source['name']}, error={error}"
                )
            results.append(result)
        save_competitor_results(product["id"], results, checked_at)
        summary["products_updated"] += 1
        summary["products"].append({
            "handle": product["handle"],
            "sources": len(results),
            "visible_prices": sum(1 for result in results if result.get("status") == "ok")
        })
    return summary


@app.route('/auth', methods=['GET'])
def auth():
    """Start Shopify OAuth install flow."""
    shop = request.args.get("shop", SHOP_URL)
    if not shop:
        return jsonify({"success": False, "message": "Missing shop parameter"}), 400
    if not SHOPIFY_CLIENT_ID or not SHOPIFY_API_SECRET:
        return jsonify({"success": False, "message": "Missing CLIENT_ID/API_SECRET"}), 500
    if not APP_URL:
        return jsonify({"success": False, "message": "Missing APP_URL"}), 500

    state = secrets.token_hex(16)
    session = shopify.Session(shop, API_VERSION)
    permission_url = session.create_permission_url(SCOPES, REDIRECT_URI, state)

    # Simple in-memory CSRF state storage
    app.config["OAUTH_STATE"] = state
    logger.info(f"🔐 OAuth start for shop: {shop}")
    return redirect(permission_url)


@app.route('/auth/callback', methods=['GET'])
def auth_callback():
    """Complete Shopify OAuth flow and store token for this shop."""
    params = request.args.to_dict()
    shop = params.get("shop")
    state = params.get("state")
    code = params.get("code")

    if not shop or not code or not state:
        return jsonify({"success": False, "message": "Missing OAuth params"}), 400
    if state != app.config.get("OAUTH_STATE"):
        return jsonify({"success": False, "message": "Invalid OAuth state"}), 400
    if not validate_hmac(params):
        return jsonify({"success": False, "message": "Invalid HMAC signature"}), 400

    try:
        session = shopify.Session(shop, API_VERSION)
        token = session.request_token(params)
        save_shop_token(shop, token)
        logger.info(f"✅ OAuth success. Token saved for shop: {shop}")
        return jsonify({
            "success": True,
            "message": "Shop installed successfully",
            "shop": shop
        }), 200
    except Exception as e:
        logger.error(f"❌ OAuth callback error: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/webhooks/app-uninstalled', methods=['POST'])
def webhook_app_uninstalled():
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")
    shop_domain = request.headers.get("X-Shopify-Shop-Domain", "")
    raw_body = request.get_data()

    if not verify_webhook_hmac(raw_body, hmac_header):
        logger.warning("⚠️ Invalid webhook HMAC for app/uninstalled")
        return jsonify({"success": False, "message": "Invalid webhook signature"}), 401

    if not shop_domain:
        return jsonify({"success": False, "message": "Missing shop domain header"}), 400

    delete_shop_token(shop_domain)
    logger.info(f"🗑️ app/uninstalled webhook processed. Token removed for {shop_domain}")
    return jsonify({"success": True}), 200


@app.route('/', methods=['GET'])
def app_index():
    """Entry point for embedded app open from Shopify Admin."""
    shop = request.args.get("shop")

    # If app is opened from Shopify and no token is available, restart OAuth.
    if shop and not get_shop_token(shop):
        return redirect(f"/auth?shop={shop}")

    html = """
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Custom Checkout Backend Logs</title>
      <style>
        body { font-family: Menlo, Monaco, Consolas, monospace; background: #111827; color: #e5e7eb; margin: 0; }
        .wrap { max-width: 1100px; margin: 0 auto; padding: 16px; }
        .top { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; margin-bottom: 12px; }
        .badge { background: #1f2937; border: 1px solid #374151; border-radius: 8px; padding: 6px 10px; }
        .panel { background: #0b1220; border: 1px solid #374151; border-radius: 10px; padding: 12px; }
        pre { white-space: pre-wrap; word-break: break-word; margin: 0; font-size: 12px; line-height: 1.45; max-height: 72vh; overflow: auto; }
      </style>
    </head>
    <body>
      <div class="wrap">
        <div class="top">
          <div class="badge">Shop: {{ shop }}</div>
          <div class="badge">Installed: {{ installed_shops }}</div>
          <div class="badge">Updated every 2s</div>
        </div>
        <div class="panel">
          <pre id="logs">Loading logs...</pre>
        </div>
      </div>
      <script>
        async function loadLogs() {
          try {
            const res = await fetch('/api/logs?limit=300');
            const data = await res.json();
            document.getElementById('logs').textContent = (data.logs || []).join('\\n');
          } catch (e) {
            document.getElementById('logs').textContent = 'Failed to load logs: ' + e;
          }
        }
        loadLogs();
        setInterval(loadLogs, 2000);
      </script>
    </body>
    </html>
    """
    return render_template_string(
        html,
        shop=(shop or SHOP_URL),
        installed_shops=", ".join(list_installed_shops()) or "none"
    )


@app.route('/favicon.ico', methods=['GET'])
def favicon():
    return "", 204


@app.route('/health', methods=['GET'])
def health_check():
    """Проверка работоспособности сервера"""
    logger.info("🏥 Health check запрос")
    return jsonify({
        'status': 'ok',
        'shop': SHOP_URL,
        'installed_shops': list_installed_shops(),
        'api_version': API_VERSION,
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/api/logs', methods=['GET'])
def get_logs():
    limit = request.args.get("limit", default=200, type=int)
    if limit < 1:
        limit = 1
    if limit > 400:
        limit = 400
    return jsonify({
        "success": True,
        "count": min(limit, len(LOG_BUFFER)),
        "logs": list(LOG_BUFFER)[-limit:]
    }), 200


@app.route('/api/create-draft', methods=['POST', 'OPTIONS'])
def create_draft_order():
    """Создание draft order из данных поп-апа"""
    
    # Обработка preflight запроса
    if request.method == 'OPTIONS':
        logger.debug("🔄 CORS preflight запрос")
        return '', 204
    
    try:
        # Получение данных из запроса
        data = request.get_json()
        
        if not data:
            logger.error("❌ Пустой запрос - данные не получены")
            return jsonify({
                'success': False,
                'message': 'No data received'
            }), 400
        
        # Логирование входящих данных
        log_request_data(data)
        
        # Валидация обязательных полей
        required_fields = ['customer', 'shipping_address', 'line_items', 'email']
        missing_fields = [field for field in required_fields if field not in data]
        
        if missing_fields:
            logger.error(f"❌ Отсутствуют обязательные поля: {', '.join(missing_fields)}")
            return jsonify({
                'success': False,
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        # Проверка наличия товаров
        if not data['line_items'] or len(data['line_items']) == 0:
            logger.error("❌ Корзина пустая - нет товаров")
            return jsonify({
                'success': False,
                'message': 'Cart is empty'
            }), 400
        
        # Логирование товаров и адреса
        log_line_items(data['line_items'])
        log_shipping_address(data['shipping_address'])

        # Активируем Shopify session для нужного магазина
        request_shop = data.get("shop") or request.args.get("shop") or SHOP_URL
        active_shop = activate_shop_session(request_shop)
        logger.info(f"🏪 Active shop session: requested={request_shop}, resolved={active_shop}")
        
        # Создание draft order
        logger.info("🔨 СОЗДАНИЕ DRAFT ORDER...")
        
        draft_order = shopify.DraftOrder()
        
        # Информация о клиенте
        draft_order.email = data['email']
        draft_order.customer = {
            'first_name': data['customer']['first_name'],
            'last_name': data['customer']['last_name'],
            'email': data['email'],
            'phone': data['customer'].get('phone', ''),
            'company': data['customer'].get('company', '')
        }
        
        # Адрес доставки
        draft_order.shipping_address = {
            'first_name': data['shipping_address']['first_name'],
            'last_name': data['shipping_address']['last_name'],
            'address1': data['shipping_address']['address1'],
            'address2': data['shipping_address'].get('address2', ''),
            'company': data['shipping_address'].get('company', data['customer'].get('company', '')),
            'city': data['shipping_address']['city'],
            'province': data['shipping_address']['province'],
            'country': data['shipping_address']['country'],
            'zip': data['shipping_address']['zip'],
            'phone': data['shipping_address'].get('phone', '')
        }
        
        # Товары в заказе
        draft_order.line_items = []
        for item in data['line_items']:
            stock_snapshot = get_variant_stock_snapshot(item['variant_id'])
            stock_value = (
                str(stock_snapshot['available_qty'])
                if stock_snapshot['available_qty'] is not None
                else "unknown"
            )

            line_item = {
                'variant_id': item['variant_id'],
                'quantity': item['quantity'],
                'properties': [
                    {'name': 'stock_available', 'value': stock_value},
                    {'name': 'inventory_tracked', 'value': 'true' if stock_snapshot['tracked'] else 'false'}
                ]
            }
            draft_order.line_items.append(line_item)
        
        # Заметка к заказу
        if data.get('note'):
            draft_order.note = data['note']
        
        # Сохранение draft order
        logger.info("💾 Сохранение draft order в Shopify...")
        
        if draft_order.save():
            logger.info("=" * 80)
            logger.info("✅ DRAFT ORDER УСПЕШНО СОЗДАН!")
            logger.info("=" * 80)
            logger.info(f"🆔 Draft Order ID: {draft_order.id}")
            logger.info(f"📧 Email клиента: {mask_email(draft_order.email)}")
            logger.info(f"💰 Общая сумма: ${draft_order.total_price}")
            logger.info(f"🔗 Invoice URL: {draft_order.invoice_url}")
            logger.info(f"📅 Создан: {draft_order.created_at}")
            logger.info("=" * 80)
            
            return jsonify({
                'success': True,
                'message': 'Draft order created successfully',
                'draft_order_id': draft_order.id,
                'invoice_url': draft_order.invoice_url,
                'total_price': draft_order.total_price
            }), 200
        
        else:
            # Ошибки валидации от Shopify
            errors = draft_order.errors.full_messages()
            logger.error("=" * 80)
            logger.error("❌ ОШИБКА ПРИ СОЗДАНИИ DRAFT ORDER")
            logger.error("=" * 80)
            logger.error(f"Ошибки валидации: {errors}")
            logger.error("=" * 80)
            
            return jsonify({
                'success': False,
                'message': 'Failed to create draft order',
                'errors': errors
            }), 400
    
    except Exception as e:
        logger.error("=" * 80)
        logger.error("❌ КРИТИЧЕСКАЯ ОШИБКА")
        logger.error("=" * 80)
        logger.error(f"Тип ошибки: {type(e).__name__}")
        logger.error(f"Сообщение: {str(e)}")
        logger.error("=" * 80)
        
        import traceback
        logger.error(f"Traceback:\n{traceback.format_exc()}")
        
        return jsonify({
            'success': False,
            'message': f'Server error: {str(e)}'
        }), 500
    finally:
        shopify.ShopifyResource.clear_session()


@app.route('/api/exit-survey', methods=['POST', 'OPTIONS'])
def create_exit_survey():
    """Store an anonymous exit-intent survey response as a Shopify Metaobject."""
    if request.method == 'OPTIONS':
        return '', 204

    if exit_survey_rate_limited():
        return jsonify({
            'success': False,
            'message': 'Too many survey submissions. Please try again later.'
        }), 429

    try:
        data = request.get_json(silent=True) or {}
        reason = str(data.get('reason') or '').strip()[:160]
        comment = str(data.get('comment') or '').strip()[:500]
        page_url = str(data.get('page_url') or '').strip()[:1000]
        page_title = str(data.get('page_title') or '').strip()[:200]
        locale = str(data.get('locale') or '').strip()[:20]
        trigger = str(data.get('trigger') or '').strip()[:50]
        source = str(data.get('source') or 'exit_intent_survey').strip()[:80]
        submitted_at = str(data.get('submitted_at') or '').strip()

        if not reason:
            return jsonify({
                'success': False,
                'message': 'Missing required field: reason'
            }), 400

        try:
            parsed_submitted_at = datetime.fromisoformat(submitted_at.replace('Z', '+00:00'))
            normalized_submitted_at = parsed_submitted_at.isoformat()
        except (TypeError, ValueError):
            normalized_submitted_at = datetime.utcnow().isoformat() + 'Z'

        request_shop = data.get('shop') or request.args.get('shop') or SHOP_URL
        if not request_shop:
            return jsonify({
                'success': False,
                'message': 'Shop is not configured.'
            }), 500

        active_shop = activate_shop_session(request_shop)
        logger.info(
            f"📊 Exit survey: shop={active_shop}, reason={mask_text(reason, keep=12)}, "
            f"locale={locale or 'unknown'}, trigger={trigger or 'unknown'}"
        )

        metaobject = create_exit_survey_metaobject({
            'reason': reason,
            'comment': comment,
            'page_url': page_url,
            'page_title': page_title,
            'locale': locale,
            'trigger': trigger,
            'source': source,
            'submitted_at': normalized_submitted_at
        })

        logger.info(f"✅ Exit survey saved: {metaobject['id']}")
        return jsonify({
            'success': True,
            'message': 'Survey response saved successfully.',
            'metaobject_id': metaobject['id']
        }), 201

    except Exception as e:
        logger.exception("❌ Error in /api/exit-survey")
        return jsonify({
            'success': False,
            'message': f'Server error: {str(e)}'
        }), 500
    finally:
        shopify.ShopifyResource.clear_session()


@app.route('/api/exit-customer', methods=['POST', 'OPTIONS'])
def create_exit_customer():
    """Создание customer из exit-intent popup"""

    if request.method == 'OPTIONS':
        logger.debug("🔄 CORS preflight запрос для /api/exit-customer")
        return '', 204

    try:
        data = request.get_json()

        if not data:
            logger.error("❌ Пустой запрос - данные не получены")
            return jsonify({
                'success': False,
                'message': 'No data received'
            }), 400

        customer_data = data.get('customer') or {}
        first_name = (customer_data.get('first_name') or '').strip()
        phone = (customer_data.get('phone') or '').strip()
        tag = (data.get('tag') or 'exit').strip()

        log_exit_customer_request(data)

        if not first_name or not phone:
            logger.error("❌ Отсутствует имя или телефон")
            return jsonify({
                'success': False,
                'message': 'Missing required fields: customer.first_name, customer.phone'
            }), 400

        request_shop = data.get("shop") or request.args.get("shop") or SHOP_URL
        active_shop = activate_shop_session(request_shop)
        logger.info(f"🏪 Active shop session: requested={request_shop}, resolved={active_shop}")

        logger.info("🔨 СОЗДАНИЕ CUSTOMER...")

        customer = shopify.Customer()
        customer.first_name = first_name
        customer.phone = phone
        customer.tags = tag

        if customer.save():
            logger.info("=" * 80)
            logger.info("✅ CUSTOMER УСПЕШНО СОЗДАН!")
            logger.info("=" * 80)
            logger.info(f"🆔 Customer ID: {customer.id}")
            logger.info(f"👤 Имя: {mask_text(customer.first_name)}")
            logger.info(f"📞 Телефон: {mask_phone(customer.phone)}")
            logger.info(f"🏷️ Теги: {customer.tags}")
            logger.info("=" * 80)

            return jsonify({
                'success': True,
                'message': 'Customer created successfully',
                'customer_id': customer.id,
                'tags': customer.tags
            }), 200

        errors = customer.errors.full_messages()
        logger.error("=" * 80)
        logger.error("❌ ОШИБКА ПРИ СОЗДАНИИ CUSTOMER")
        logger.error("=" * 80)
        logger.error(f"Ошибки валидации: {errors}")
        logger.error("=" * 80)

        return jsonify({
            'success': False,
            'message': 'Failed to create customer',
            'errors': errors
        }), 400

    except Exception as e:
        logger.error("=" * 80)
        logger.error("❌ КРИТИЧЕСКАЯ ОШИБКА В /api/exit-customer")
        logger.error("=" * 80)
        logger.error(f"Тип ошибки: {type(e).__name__}")
        logger.error(f"Сообщение: {str(e)}")
        logger.error("=" * 80)

        import traceback
        logger.error(f"Traceback:\n{traceback.format_exc()}")

        return jsonify({
            'success': False,
            'message': f'Server error: {str(e)}'
        }), 500
    finally:
        shopify.ShopifyResource.clear_session()


@app.route('/api/competitor-prices/setup', methods=['POST'])
def setup_competitor_prices():
    """Create the product metafield definitions used by the price monitor."""
    if not competitor_request_is_authorized():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    try:
        request_shop = request.args.get("shop") or SHOP_URL
        activate_shop_session(request_shop)
        result = ensure_competitor_metafield_definitions()
        logger.info(f"✅ Competitor price metafields ready: {result}")
        return jsonify({'success': True, **result}), 200
    except Exception as error:
        logger.exception("❌ Error in /api/competitor-prices/setup")
        return jsonify({'success': False, 'message': str(error)}), 500
    finally:
        shopify.ShopifyResource.clear_session()


@app.route('/api/competitor-prices/refresh', methods=['POST'])
def refresh_competitor_prices_endpoint():
    """Refresh all tagged products; intended for a once-daily Render Cron Job."""
    if not competitor_request_is_authorized():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    try:
        request_shop = request.args.get("shop") or SHOP_URL
        activate_shop_session(request_shop)
        ensure_competitor_metafield_definitions()
        summary = refresh_competitor_prices()
        logger.info(f"✅ Competitor price refresh completed: {summary}")
        return jsonify({'success': True, **summary}), 200
    except Exception as error:
        logger.exception("❌ Error in /api/competitor-prices/refresh")
        return jsonify({'success': False, 'message': str(error)}), 500
    finally:
        shopify.ShopifyResource.clear_session()


@app.route('/api/test', methods=['GET'])
def test_connection():
    """Тестовый endpoint для проверки подключения к Shopify"""
    logger.info("🧪 Тестирование подключения к Shopify...")
    
    try:
        request_shop = request.args.get("shop") or SHOP_URL
        activate_shop_session(request_shop)
        shop = shopify.Shop.current()
        logger.info(f"✅ Подключение успешно! Магазин: {shop.name}")
        
        return jsonify({
            'success': True,
            'shop_name': shop.name,
            'shop_email': shop.email,
            'shop_domain': shop.domain,
            'currency': shop.currency
        }), 200
    
    except Exception as e:
        logger.error(f"❌ Ошибка подключения: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500
    finally:
        shopify.ShopifyResource.clear_session()


if __name__ == '__main__':
    logger.info("=" * 80)
    logger.info("🚀 ЗАПУСК СЕРВЕРА")
    logger.info("=" * 80)
    logger.info(f"🏪 Магазин: {SHOP_URL}")
    logger.info(f"📡 API версия: {API_VERSION}")
    logger.info(f"🔌 Порт: {PORT}")
    logger.info(f"🔗 Endpoints:")
    logger.info(f"   - POST http://localhost:{PORT}/api/create-draft")
    logger.info(f"   - POST http://localhost:{PORT}/api/exit-survey")
    logger.info(f"   - POST http://localhost:{PORT}/api/competitor-prices/setup")
    logger.info(f"   - POST http://localhost:{PORT}/api/competitor-prices/refresh")
    logger.info(f"   - GET  http://localhost:{PORT}/api/test")
    logger.info(f"   - GET  http://localhost:{PORT}/health")
    logger.info(f"   - POST http://localhost:{PORT}/webhooks/app-uninstalled")
    logger.info("=" * 80)
    
    app.run(
        host='0.0.0.0',
        port=PORT,
        debug=True
    )
