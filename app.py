import os
import json
import logging
import secrets
import hmac
import hashlib
import base64
import sqlite3
from collections import deque
from datetime import datetime
from flask import Flask, request, jsonify, redirect, render_template_string
from flask_cors import CORS
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
SHOPIFY_SCOPES = os.getenv("SCOPES", "read_products,write_products,write_inventory")
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
    if not token:
        raise ValueError(f"No access token for shop: {shop_domain}. Install app via /auth first.")
    session = shopify.Session(shop_domain, API_VERSION, token)
    shopify.ShopifyResource.activate_session(session)


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
        activate_shop_session(request_shop)
        
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
            line_item = {
                'variant_id': item['variant_id'],
                'quantity': item['quantity']
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
    logger.info(f"   - GET  http://localhost:{PORT}/api/test")
    logger.info(f"   - GET  http://localhost:{PORT}/health")
    logger.info(f"   - POST http://localhost:{PORT}/webhooks/app-uninstalled")
    logger.info("=" * 80)
    
    app.run(
        host='0.0.0.0',
        port=PORT,
        debug=True
    )
