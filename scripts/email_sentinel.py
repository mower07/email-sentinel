#!/usr/bin/env python3
"""
Email Sentinel — automated email classifier and security scanner for AI agents.

SECURITY MANIFEST:
  Env variables accessed: TELEGRAM_BOT_TOKEN (optional), EMAIL_SENTINEL_CONFIG (optional),
                          account password_env values defined in config.json
  External endpoints: api.telegram.org (delivery), imap.yandex.ru (Yandex IMAP),
                      Gmail API (googleapis.com), List-Unsubscribe URLs (HTTP GET/POST)
  Local files written: paths defined in config.json > logs section
  Local files read: config.json, Gmail OAuth2 token files, ~/.env
  No data is sent to third-party analytics or telemetry services.

Usage:
  python email_sentinel.py --dry-run             # classify only, no actions
  python email_sentinel.py --execute             # classify + execute actions
  python email_sentinel.py --execute --max 50    # limit to 50 emails per account
  python email_sentinel.py --digest              # send digest to Telegram
  python email_sentinel.py --daily-report        # send daily stats report
  python email_sentinel.py --resend-show         # resend queued show_to_owner items
  python email_sentinel.py --clean-promos        # unsubscribe + delete promotions
  python email_sentinel.py --account personal    # run on specific account only
  python email_sentinel.py --setup               # run setup wizard
"""

import os, sys, json, base64, re, argparse, urllib.request, urllib.parse
import imaplib, email as email_lib
from datetime import datetime
from pathlib import Path

# ─── load .env ───────────────────────────────────────────────────────────────
def _load_dotenv(path=None):
    for candidate in [path, os.path.expanduser("~/.env"), ".env"]:
        if candidate and os.path.exists(candidate):
            with open(candidate) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip())
            break

_load_dotenv()

# ─── config ───────────────────────────────────────────────────────────────────
_CONFIG_PATH = os.environ.get(
    "EMAIL_SENTINEL_CONFIG",
    os.path.join(os.path.dirname(__file__), "config.json"),
)

def load_config() -> dict:
    if not os.path.exists(_CONFIG_PATH):
        print(f"[ERROR] config.json not found at {_CONFIG_PATH}")
        print("Run --setup or copy config.template.json to config.json and edit.")
        sys.exit(1)
    with open(_CONFIG_PATH) as f:
        return json.load(f)

CFG = load_config()

# ─── telegram ─────────────────────────────────────────────────────────────────
def _get_bot_token() -> str:
    tg = CFG.get("telegram", {})
    env_name = tg.get("bot_token_env", "TELEGRAM_BOT_TOKEN")
    token = os.environ.get(env_name, "") or tg.get("bot_token_direct", "")
    if not token:
        raise RuntimeError(
            f"Telegram bot token not found. Set {env_name} env var or bot_token_direct in config.json"
        )
    return token

def html_esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def send_telegram(chat_id, text, thread_id=None) -> bool:
    if not chat_id:
        return False
    try:
        token = _get_bot_token()
        payload: dict = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
        if thread_id:
            payload["message_thread_id"] = thread_id
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        resp = json.loads(urllib.request.urlopen(req, timeout=10).read())
        return resp.get("ok", False)
    except Exception as e:
        print(f"  [TG ERROR] {e}")
        return False

# Telegram target shortcuts
_TG = CFG.get("telegram", {}).get("targets", {})
TG_OWNER          = _TG.get("owner_chat_id") or 0
TG_PARTNERS       = _TG.get("partners_chat_id")
TG_SALES_CHAT     = _TG.get("sales_chat_id")
TG_SALES_THREAD   = _TG.get("sales_chat_thread_id")
TG_SUPPORT_CHAT   = _TG.get("support_chat_id")
TG_SUPPORT_THREAD = _TG.get("support_chat_thread_id")
TG_SALES_MENTION  = _TG.get("sales_mention", "")
TG_SUPPORT_MENTION = _TG.get("support_mention", "")

# ─── log paths ────────────────────────────────────────────────────────────────
_LOGS = CFG.get("logs", {})
def _log_path(key, default):
    p = _LOGS.get(key, default)
    return os.path.expanduser(p)

PROCESSING_LOG = _log_path("processing_log",  "~/.email-sentinel/email-runs.jsonl")
SHOW_LOG       = _log_path("show_queue",       "~/.email-sentinel/show-queue.json")
DIGEST_LOG     = _log_path("digest_queue",     "~/.email-sentinel/digest-queue.json")
LEADS_LOG      = _log_path("leads_log",        "~/.email-sentinel/leads.md")

for _p in [PROCESSING_LOG, SHOW_LOG, DIGEST_LOG, LEADS_LOG]:
    os.makedirs(os.path.dirname(_p), exist_ok=True)

# ─── limits ───────────────────────────────────────────────────────────────────
_LIMITS = CFG.get("limits", {})
DEFAULT_MAX_EMAILS   = _LIMITS.get("max_emails_per_run", 100)
EMAIL_BOMB_THRESHOLD = _LIMITS.get("email_bomb_threshold", 150)
PROMOS_MAX           = _LIMITS.get("promotions_cleanup_per_run", 30)

# ─── accounts ─────────────────────────────────────────────────────────────────
ACCOUNTS: dict = CFG.get("accounts", {})

# ─── classification config ────────────────────────────────────────────────────
_CLS = CFG.get("classification", {})

SPAM_SENDERS          = set(_CLS.get("spam_senders", []))
SPAM_SENDER_DOMAINS   = set(_CLS.get("spam_sender_domains", []))
ARCHIVE_SENDERS       = set(_CLS.get("archive_senders", []))
ARCHIVE_SENDER_DOMAINS = set(_CLS.get("archive_sender_domains", []))
NEWSLETTER_DOMAINS    = set(_CLS.get("newsletter_sender_domains", []))
TRUSTED_INTERNAL      = set(_CLS.get("trusted_internal_domains", []))
SUPPLIER_KEYWORDS     = _CLS.get("supplier_keywords", [
    "коммерческое предложение", "прайс", "КП ", "поставка", "оптовые цены",
    "proposal", "price list", "quotation", "wholesale",
])
LEAD_KEYWORDS         = _CLS.get("lead_subject_keywords", [])
LEAD_RE_STR           = _CLS.get("lead_subject_regex", "")
LEAD_RE               = re.compile(LEAD_RE_STR, re.I) if LEAD_RE_STR else None
ROUTING               = _CLS.get("routing", {})

# ─── built-in classification patterns ────────────────────────────────────────

# Security / gov authorities
SECURITY_RE = re.compile(
    r"(суд |арбитражн|роскомнадзор|прокурат"
    r"|ип прекращ|ликвидаци|банкротств|исполнительн|судебн пристав"
    r"|требование.*уплат|задолженность.*бюджет|фнс|налоговая инспекц)",
    re.I,
)

# YooMoney receipts
YOOMONEY_RE = re.compile(r"yoomoney|юmoney", re.I)

# Cloudpayments / payment processors → archive
CLOUDPAYMENTS_RE = re.compile(
    r"(noreply-cloudpayments|noreply-cloudkassir|cloudkassir|cloudpayments)", re.I
)

# Telegram verification codes → delete silently (they expire)
TELEGRAM_VERIFY_RE = re.compile(r"noreply@telegram\.org", re.I)

# Urgency / phishing signals
URGENCY_RE = re.compile(
    r"(urgent|срочно|немедленно|аккаунт.*заблокир|последнее предупреждение"
    r"|verify.*account|подтвердите.*вход|unusual.*activity)",
    re.I,
)

# Service sender domains (→ archive)
SERVICE_SENDER_DOMAINS = {
    "github.com", "tldv.io", "zoom.us", "notion.so",
    "accounts.google.com", "google.com", "gamma.app",
    "id.yandex.ru", "id.yandex.com",
    "accountprotection.microsoft.com",
}

# Newsletter signals
NEWSLETTER_RE = re.compile(
    r"(unsubscribe|отписат|дайджест|подборка|еженедельн|ежемесячн"
    r"|новости отрасли|обзор рынка|акция|скидка|рассылка)",
    re.I,
)

# ─── helpers ──────────────────────────────────────────────────────────────────

def strip_html(raw: str, max_chars: int = 800) -> str:
    """
    Strip HTML tags and sanitize before passing to LLM or classifier.
    Removes: tags, HTML entities, zero-width chars, excess whitespace.
    ALWAYS apply this before passing email body to any LLM context.
    """
    text = re.sub(r'<[^>]+>', ' ', raw)
    import html as html_lib
    text = html_lib.unescape(text)
    # remove zero-width and invisible unicode
    text = re.sub(r'[\u200b\u200c\u200d\ufeff\u00ad\u2028\u2029]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:max_chars]

def parse_sender(raw_from: str):
    """Return (display_name, email_address) from a From header."""
    m = re.search(r'<([^>]+)>', raw_from)
    email_addr = m.group(1).lower().strip() if m else raw_from.lower().strip()
    display    = re.sub(r'\s*<[^>]+>', '', raw_from).strip().strip('"')
    return display, email_addr

def sender_domain(email_addr: str) -> str:
    return email_addr.split("@")[-1].lower() if "@" in email_addr else ""

def is_supplier(subject: str, body: str) -> bool:
    text = (subject + " " + body).lower()
    return any(kw.lower() in text for kw in SUPPLIER_KEYWORDS)

def is_lead(subject: str, body: str) -> bool:
    if not LEAD_RE and not LEAD_KEYWORDS:
        return False
    text = (subject + " " + body).lower()
    if LEAD_RE and LEAD_RE.search(subject):
        return True
    return any(kw.lower() in text for kw in LEAD_KEYWORDS)

# ─── Gmail API ────────────────────────────────────────────────────────────────

def _get_gmail_service(cfg: dict):
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request
    from googleapiclient.discovery import build

    token_path = os.path.expanduser(cfg["token_path"])
    SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
    creds = Credentials.from_authorized_user_file(token_path, SCOPES)
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        with open(token_path, "w") as f:
            f.write(creds.to_json())
    return build("gmail", "v1", credentials=creds)

def get_body_text(payload, max_chars: int = 800) -> str:
    """Extract plain text from Gmail message payload."""
    text = ""
    if "parts" in payload:
        for part in payload["parts"]:
            ct = part.get("mimeType", "")
            if ct == "text/plain":
                data = part.get("body", {}).get("data", "")
                if data:
                    text += base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
                    if len(text) >= max_chars:
                        break
            elif ct.startswith("multipart/"):
                text += get_body_text(part, max_chars)
    else:
        data = payload.get("body", {}).get("data", "")
        if data:
            raw = base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
            ct  = payload.get("mimeType", "")
            text = strip_html(raw) if "html" in ct else raw
    return text[:max_chars]

# ─── IMAP (Yandex + generic) ──────────────────────────────────────────────────

def _imap_get_body(msg_obj, max_chars: int = 800) -> str:
    text = ""
    if msg_obj.is_multipart():
        for part in msg_obj.walk():
            if part.get_content_type() == "text/plain":
                try:
                    raw = part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
                    text += strip_html(raw)
                except Exception:
                    pass
                if len(text) >= max_chars:
                    break
    else:
        try:
            raw = msg_obj.get_payload(decode=True).decode(
                msg_obj.get_content_charset() or "utf-8", errors="replace"
            )
            text = strip_html(raw)
        except Exception:
            text = ""
    return text[:max_chars]

def _imap_execute(imap, uid, action: str, headers: dict):
    uid_b = uid if isinstance(uid, bytes) else uid.encode()
    if action == "delete":
        try_unsubscribe(headers)
        for trash in ("Trash", "INBOX.Trash"):
            try:
                imap.uid("COPY", uid_b, trash)
                break
            except Exception:
                pass
        imap.uid("STORE", uid_b, "+FLAGS", r"(\Deleted)")
        imap.expunge()
    elif action == "move_to_spam":
        for spam in ("Spam", "INBOX.Spam", "Junk"):
            try:
                imap.uid("COPY", uid_b, spam)
                break
            except Exception:
                pass
        imap.uid("STORE", uid_b, "+FLAGS", r"(\Seen \Deleted)")
        imap.expunge()
    else:
        imap.uid("STORE", uid_b, "+FLAGS", r"(\Seen)")

# ─── classify ────────────────────────────────────────────────────────────────

def classify(sender_email: str, sender_name: str, subject: str, body: str, logic: str = "personal"):
    """
    Returns (category, action, priority, reason).

    Actions:   delete | move_to_spam | archive | collect_for_digest
               show_to_owner | alert_owner | alert_support | forward_to_partners
               forward_to_sales | save_for_lead
    Priority:  high | medium | low
    """
    se  = sender_email.lower().strip()
    dom = sender_domain(se)
    sub = subject or ""
    txt = (sub + " " + body).lower()

    # 0. Internal domain → archive silently
    if dom in TRUSTED_INTERNAL:
        return "internal", "archive", "low", f"internal domain ({dom})"

    # 1. Known spam
    if se in SPAM_SENDERS or dom in SPAM_SENDER_DOMAINS:
        return "spam", "move_to_spam", "low", f"known spam sender ({se or dom})"

    # 2. Telegram verification codes → delete
    if TELEGRAM_VERIFY_RE.search(se):
        return "service", "delete", "low", "Telegram verification code (expires) → delete"

    # 3. Cloudpayments / known archive services
    if CLOUDPAYMENTS_RE.search(se) or se in ARCHIVE_SENDERS or dom in ARCHIVE_SENDER_DOMAINS:
        return "service", "archive", "low", f"known service/payment sender"

    # 4. Service sender domains
    if dom in SERVICE_SENDER_DOMAINS:
        return "service", "archive", "low", f"service notification ({dom})"

    # 5. YooMoney receipts
    if YOOMONEY_RE.search(se):
        amount_m = re.search(r"(\d[\d\s]*[\.,]\d{2})\s*(руб|₽|rub)", txt, re.I)
        if amount_m:
            return "financial", "show_to_owner", "medium", f"YooMoney receipt {amount_m.group(0)}"
        return "financial", "archive", "low", "YooMoney no-amount receipt → archive"

    # 6. Security / government authorities
    if SECURITY_RE.search(sub) or SECURITY_RE.search(body[:300]):
        return "gov_alert", "alert_owner", "high", "government authority or legal threat"

    # 7. Supplier / КП (if routing enabled)
    if ROUTING.get("forward_suppliers_to_partners_chat") and is_supplier(sub, body):
        return "supplier", "forward_to_partners", "medium", "supplier proposal/price list"

    # 8. Lead (if routing enabled)
    if ROUTING.get("forward_leads_to_sales_chat") and is_lead(sub, body):
        return "lead", "forward_to_sales", "medium", "potential client lead"

    # 9. Newsletter / mailing list
    if dom in NEWSLETTER_DOMAINS or NEWSLETTER_RE.search(sub):
        return "newsletter", "collect_for_digest", "low", f"newsletter/mailing list"

    # 10. Urgency signals → show to owner
    if URGENCY_RE.search(sub):
        return "phishing_signal", "show_to_owner", "high", "urgency keywords in subject"

    # 11. Unknown → show to owner
    return "other", "show_to_owner", "medium", "unclassified — review manually"

# ─── action labels ────────────────────────────────────────────────────────────

PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}
CAT_LABEL = {
    "spam": "СПАМ", "service": "СЕРВИС", "financial": "ФИНАНСЫ",
    "gov_alert": "БЕЗОПАСНОСТЬ", "supplier": "ПОСТАВЩИК", "lead": "ЛИД",
    "newsletter": "РАССЫЛКА", "phishing_signal": "ФИШИНГ-СИГНАЛ",
    "internal": "ВНУТРЕННЕЕ", "other": "ДРУГОЕ",
}
ACTION_LABEL = {
    "delete":             "🗑  удалить",
    "move_to_spam":       "🚫 спам",
    "archive":            "📂 архив",
    "collect_for_digest": "📋 дайджест",
    "show_to_owner":      "👁  показать владельцу",
    "alert_owner":        "🚨 АЛЕРТ владельцу",
    "alert_support":      "⚠️ → Support",
    "forward_to_partners":"📨 → партнёры",
    "forward_to_sales":   "📨 → продажи",
    "save_for_lead":      "🎯 → лиды",
}

# ─── execute action ───────────────────────────────────────────────────────────

def execute_action_gmail(service, msg_id: str, action: str, item: dict, headers: dict = None):
    if action == "delete":
        if headers:
            try_unsubscribe(headers)
        service.users().messages().trash(userId="me", id=msg_id).execute()
    elif action == "move_to_spam":
        service.users().messages().modify(
            userId="me", id=msg_id,
            body={"addLabelIds": ["SPAM"], "removeLabelIds": ["INBOX"]},
        ).execute()
    elif action == "archive":
        service.users().messages().modify(
            userId="me", id=msg_id,
            body={"removeLabelIds": ["INBOX", "UNREAD"]},
        ).execute()
    elif action == "collect_for_digest":
        service.users().messages().modify(
            userId="me", id=msg_id,
            body={"removeLabelIds": ["INBOX", "UNREAD"]},
        ).execute()
        _append_digest(item)
    elif action == "save_for_lead":
        service.users().messages().modify(
            userId="me", id=msg_id,
            body={"removeLabelIds": ["UNREAD"]},
        ).execute()
        _append_lead(item)
    else:
        # show_to_owner / alert_owner / alert_support / forward_* → mark read
        service.users().messages().modify(
            userId="me", id=msg_id,
            body={"removeLabelIds": ["UNREAD"]},
        ).execute()

# ─── unsubscribe ──────────────────────────────────────────────────────────────

def try_unsubscribe(headers: dict) -> str:
    header = headers.get("List-Unsubscribe", "") or headers.get("list-unsubscribe", "")
    if not header:
        return "no_header"
    # RFC 8058 One-Click POST
    post_m = re.search(r'<(https?://[^>]+)>', header)
    lup = headers.get("List-Unsubscribe-Post", "") or headers.get("list-unsubscribe-post", "")
    if post_m and "one-click" in lup.lower():
        try:
            url = post_m.group(1)
            body = b"List-Unsubscribe=One-Click"
            req  = urllib.request.Request(url, data=body,
                                          headers={"Content-Type": "application/x-www-form-urlencoded"})
            urllib.request.urlopen(req, timeout=8)
            return "ok_post"
        except Exception:
            pass
    # Fallback: GET
    get_m = re.search(r'<(https?://[^>]+)>', header)
    if get_m:
        try:
            urllib.request.urlopen(get_m.group(1), timeout=8)
            return "ok_get"
        except Exception:
            pass
    return "failed"

# ─── logs ─────────────────────────────────────────────────────────────────────

def _append_digest(item: dict):
    q = []
    if os.path.exists(DIGEST_LOG):
        with open(DIGEST_LOG) as f:
            q = json.load(f)
    q.append(item)
    with open(DIGEST_LOG, "w") as f:
        json.dump(q, f, ensure_ascii=False, indent=2)

def _append_lead(item: dict):
    with open(LEADS_LOG, "a") as f:
        f.write(f"\n## {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"**От:** {item.get('from','')}\n")
        f.write(f"**Тема:** {item.get('subject','')}\n")
        f.write(f"**Причина:** {item.get('reason','')}\n\n")

def log_run_stats(by_action: dict, accounts_run: list):
    entry = {
        "ts": datetime.now().isoformat(),
        "accounts": accounts_run,
        "stats": {k: len(v) for k, v in by_action.items()},
    }
    with open(PROCESSING_LOG, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def save_show_items(items: list):
    data = {"ts": datetime.now().timestamp(), "items": items}
    with open(SHOW_LOG, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# ─── run account: Gmail ───────────────────────────────────────────────────────

def run_account_gmail(account_key: str, max_emails: int, dry_run: bool) -> list:
    cfg = ACCOUNTS[account_key]
    print(f"\n{'='*60}")
    print(f"📬 {cfg['label']} ({cfg['email']})")
    print(f"{'='*60}")

    service = _get_gmail_service(cfg)
    result  = service.users().messages().list(
        userId="me", q="is:unread", maxResults=max_emails
    ).execute()
    msg_ids = [m["id"] for m in result.get("messages", [])]

    if not msg_ids:
        print("no unread emails")
        return []

    unread_total = int(service.users().labels().get(userId="me", id="INBOX").execute().get("messagesUnread", 0))
    if unread_total > EMAIL_BOMB_THRESHOLD:
        print(f"⚠️  EMAIL BOMB WARNING: {unread_total} unread (>{EMAIL_BOMB_THRESHOLD}) — alerting owner")
        send_telegram(TG_OWNER, f"⚠️ <b>Email bomb alert</b>\n\n{unread_total} unread in {cfg['email']}. Processing capped at {max_emails}. Review manually.")

    print(f"unread: {len(msg_ids)}\n")

    classified = []
    for mid in msg_ids:
        msg     = service.users().messages().get(userId="me", id=mid, format="full").execute()
        hdrs    = {h["name"]: h["value"] for h in msg["payload"]["headers"]}
        raw_from = hdrs.get("From", "")
        subject  = hdrs.get("Subject", "(no subject)")
        date_str = hdrs.get("Date", "")
        body     = strip_html(get_body_text(msg["payload"]))

        name, addr = parse_sender(raw_from)
        cat, action, priority, reason = classify(addr, name, subject, body, cfg.get("logic", "personal"))

        item = {
            "id": mid, "from": raw_from, "subject": subject,
            "date": date_str, "category": cat, "action": action,
            "priority": priority, "reason": reason,
            "account_label": cfg["label"],
        }
        classified.append(item)
        if not dry_run:
            execute_action_gmail(service, mid, action, item, headers=hdrs)

    classified.sort(key=lambda x: PRIORITY_ORDER.get(x["priority"], 9))
    _print_classified(classified)
    return classified

# ─── run account: IMAP ────────────────────────────────────────────────────────

def run_account_imap(account_key: str, max_emails: int, dry_run: bool) -> list:
    cfg = ACCOUNTS[account_key]
    print(f"\n{'='*60}")
    print(f"📬 {cfg['label']} ({cfg['email']})")
    print(f"{'='*60}")

    password = os.environ.get(cfg.get("password_env", ""), "")
    if not password:
        print(f"  [ERROR] password env var not set: {cfg.get('password_env')}")
        return []

    try:
        imap = imaplib.IMAP4_SSL(cfg.get("host", "imap.yandex.ru"), int(cfg.get("port", 993)))
        imap.login(cfg["email"], password)
    except Exception as e:
        print(f"  [IMAP ERROR] {e}")
        return []

    imap.select("INBOX")
    _, data = imap.uid("SEARCH", None, "UNSEEN")
    uid_list = (data[0].split() if data[0] else [])[:max_emails]

    if not uid_list:
        print("no unread emails")
        imap.logout()
        return []

    print(f"unread: {len(uid_list)}\n")

    classified = []
    for uid in uid_list:
        try:
            _, raw = imap.uid("FETCH", uid, "(RFC822)")
            if not raw or not raw[0]:
                continue
            msg_obj = email_lib.message_from_bytes(raw[0][1])

            def _hdr(name):
                val = msg_obj.get(name, "")
                parts = email_lib.header.decode_header(val)
                return " ".join(
                    p.decode(c or "utf-8", errors="replace") if isinstance(p, bytes) else str(p)
                    for p, c in parts
                )

            raw_from = _hdr("From")
            subject  = _hdr("Subject") or "(no subject)"
            date_str = _hdr("Date")
            hdrs     = {k: _hdr(k) for k in msg_obj.keys()}
            body     = _imap_get_body(msg_obj)

            name, addr = parse_sender(raw_from)
            cat, action, priority, reason = classify(addr, name, subject, body, cfg.get("logic", "personal"))

            item = {
                "id": uid.decode() if isinstance(uid, bytes) else uid,
                "from": raw_from, "subject": subject, "date": date_str,
                "category": cat, "action": action,
                "priority": priority, "reason": reason,
                "account_label": cfg["label"],
            }
            classified.append(item)
            if not dry_run:
                _imap_execute(imap, uid, action, hdrs)
                if action == "collect_for_digest":
                    _append_digest(item)
                elif action == "save_for_lead":
                    _append_lead(item)
        except Exception as e:
            print(f"  [MSG ERROR] uid={uid}: {e}")

    imap.logout()
    classified.sort(key=lambda x: PRIORITY_ORDER.get(x["priority"], 9))
    _print_classified(classified)
    return classified

# ─── print classified ─────────────────────────────────────────────────────────

def _print_classified(classified: list):
    for item in classified:
        print(f"[{CAT_LABEL.get(item['category'], item['category'].upper())}] "
              f"{ACTION_LABEL.get(item['action'], item['action'])}")
        print(f"  from:    {item['from'][:55]}")
        print(f"  subject: {item['subject'][:55]}")
        print(f"  ↳ {item['reason']}")
        print()

# ─── telegram delivery ────────────────────────────────────────────────────────

def send_telegram_batches(by_action: dict):
    """Send classified results to Telegram owner and configured channels."""

    # 1. Security alerts → owner immediately
    for item in by_action.get("alert_owner", []):
        text = (f"🚨 <b>SECURITY ALERT</b>\n\n"
                f"From: {html_esc(item['from'][:60])}\n"
                f"Subject: {html_esc(item['subject'][:80])}\n"
                f"↳ {html_esc(item['reason'])}")
        send_telegram(TG_OWNER, text)

    # 2. Support alerts
    for item in by_action.get("alert_support", []):
        mention = f" {TG_SUPPORT_MENTION}" if TG_SUPPORT_MENTION else ""
        text = (f"⚠️ <b>ALERT</b>{mention}\n\n"
                f"From: {html_esc(item['from'][:60])}\n"
                f"Subject: {html_esc(item['subject'][:80])}\n"
                f"↳ {html_esc(item['reason'])}")
        send_telegram(TG_SUPPORT_CHAT, text, thread_id=TG_SUPPORT_THREAD)

    # 3. Show to owner — chunked
    show_items = by_action.get("show_to_owner", [])
    if show_items:
        header = f"📬 <b>New emails ({len(show_items)})</b>\n"
        chunk, chunk_len = [header], len(header)
        n = 1
        for it in show_items:
            acc  = it.get("account_label", "")
            line = (f"• <b>{html_esc(it['subject'][:60])}</b>\n"
                    f"  from: {html_esc(it['from'][:50])}"
                    + (f" [{html_esc(acc)}]" if acc else "")) + "\n"
            if chunk_len + len(line) > 3000:
                send_telegram(TG_OWNER, "\n".join(chunk))
                n += 1
                chunk = [f"📬 <b>New emails (cont. {n})</b>\n"]
                chunk_len = len(chunk[0])
            chunk.append(line)
            chunk_len += len(line)
        if chunk:
            send_telegram(TG_OWNER, "\n".join(chunk))

    # 4. Suppliers → partners chat
    if ROUTING.get("forward_suppliers_to_partners_chat") and TG_PARTNERS:
        partner_items = by_action.get("forward_to_partners", [])
        if partner_items:
            header = f"📨 <b>Suppliers/proposals ({len(partner_items)})</b>\n"
            chunk, chunk_len = [header], len(header)
            for it in partner_items:
                line = f"• {html_esc(it['from'][:50])}\n  {html_esc(it['subject'][:60])}\n"
                if chunk_len + len(line) > 3000:
                    send_telegram(TG_PARTNERS, "\n".join(chunk))
                    chunk, chunk_len = [], 0
                chunk.append(line)
                chunk_len += len(line)
            if chunk:
                send_telegram(TG_PARTNERS, "\n".join(chunk))

    # 5. Leads → sales chat
    if ROUTING.get("forward_leads_to_sales_chat") and TG_SALES_CHAT:
        lead_items = by_action.get("forward_to_sales", [])
        if lead_items:
            mention = TG_SALES_MENTION + " " if TG_SALES_MENTION else ""
            header  = f"🎯 <b>Leads {mention}({len(lead_items)})</b>\n"
            chunk, chunk_len = [header], len(header)
            for it in lead_items:
                line = f"• {html_esc(it['from'][:50])}\n  {html_esc(it['subject'][:60])}\n"
                if chunk_len + len(line) > 3000:
                    send_telegram(TG_SALES_CHAT, "\n".join(chunk), thread_id=TG_SALES_THREAD)
                    chunk, chunk_len = [], 0
                chunk.append(line)
                chunk_len += len(line)
            if chunk:
                send_telegram(TG_SALES_CHAT, "\n".join(chunk), thread_id=TG_SALES_THREAD)

# ─── promotions cleanup ───────────────────────────────────────────────────────

def run_promotions_cleanup(account_key: str, max_emails: int = 30, dry_run: bool = True):
    cfg = ACCOUNTS[account_key]
    if cfg.get("kind") == "imap":
        print(f"  [{cfg['label']}] promotions cleanup: not supported for IMAP accounts")
        return 0
    print(f"\n  [{cfg['label']}] checking promotions...")
    service = _get_gmail_service(cfg)
    result  = service.users().messages().list(
        userId="me", q="category:promotions is:unread", maxResults=max_emails
    ).execute()
    msgs = result.get("messages", [])
    if not msgs:
        print("  no promotions found")
        return 0

    unsub_ok = 0
    for m in msgs:
        msg  = service.users().messages().get(userId="me", id=m["id"], format="full").execute()
        hdrs = {h["name"]: h["value"] for h in msg["payload"]["headers"]}
        if not dry_run:
            r = try_unsubscribe(hdrs)
            if r.startswith("ok"):
                unsub_ok += 1
            service.users().messages().trash(userId="me", id=m["id"]).execute()

    print(f"  {'[dry]' if dry_run else ''} promotions: {len(msgs)} processed, {unsub_ok} unsubscribed")
    return len(msgs)

# ─── digest / report ──────────────────────────────────────────────────────────

def send_digest():
    if not os.path.exists(DIGEST_LOG):
        send_telegram(TG_OWNER, "📋 Digest queue is empty.")
        return
    with open(DIGEST_LOG) as f:
        items = json.load(f)
    if not items:
        send_telegram(TG_OWNER, "📋 Digest queue is empty.")
        return
    lines = [f"📋 <b>Digest ({len(items)} emails)</b>\n"]
    for it in items:
        lines.append(f"• {html_esc(it['subject'][:60])}\n  {html_esc(it['from'][:45])}\n")
    send_telegram(TG_OWNER, "\n".join(lines))
    open(DIGEST_LOG, "w").write("[]")

def send_daily_report():
    if not os.path.exists(PROCESSING_LOG):
        send_telegram(TG_OWNER, "📊 No processing log yet.")
        return
    from collections import Counter
    stats: Counter = Counter()
    cutoff = datetime.now().replace(hour=0, minute=0, second=0).isoformat()
    with open(PROCESSING_LOG) as f:
        for line in f:
            try:
                entry = json.loads(line)
                if entry.get("ts", "") >= cutoff:
                    for k, v in entry.get("stats", {}).items():
                        stats[k] += v
            except Exception:
                pass
    if not stats:
        send_telegram(TG_OWNER, "📊 <b>Daily email report</b>\n\nNo emails processed today.")
        return
    lines = ["📊 <b>Daily email report</b>\n"]
    for action, count in sorted(stats.items(), key=lambda x: -x[1]):
        lines.append(f"  {ACTION_LABEL.get(action, action)}: {count}")
    send_telegram(TG_OWNER, "\n".join(lines))

def resend_show_items():
    if not os.path.exists(SHOW_LOG):
        send_telegram(TG_OWNER, "📬 Show queue is empty.")
        return
    with open(SHOW_LOG) as f:
        data = json.load(f)
    items = data.get("items", [])
    if not items:
        send_telegram(TG_OWNER, "📬 Show queue is empty.")
        return
    # Re-send via batch logic
    by_action = {"show_to_owner": items}
    send_telegram_batches(by_action)
    print(f"Resent {len(items)} items.")

# ─── setup wizard ─────────────────────────────────────────────────────────────

def run_setup():
    print("\n🛡️  Email Sentinel — Setup\n")
    print("1. Copy config.template.json to config.json")
    print("2. Edit config.json:")
    print("   - Set telegram.targets.owner_chat_id to your Telegram user ID")
    print("   - Set telegram.bot_token_env (default: TELEGRAM_BOT_TOKEN)")
    print("   - Add your email accounts under 'accounts'")
    print("3. For Gmail: run OAuth2 authorization:")
    print("   python email_sentinel.py --auth-gmail personal")
    print("4. For Yandex IMAP: generate App Password at id.yandex.ru/security/app-passwords")
    print("   Set it as env var matching your account's password_env")
    print("5. Test: python email_sentinel.py --dry-run")
    print("\nSee README.md for detailed instructions.")

# ─── main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Email Sentinel — secure email classifier for AI agents"
    )
    parser.add_argument("--dry-run",      action="store_true", help="Classify only, no actions")
    parser.add_argument("--execute",      action="store_true", help="Classify + execute actions")
    parser.add_argument("--digest",       action="store_true", help="Send digest to Telegram")
    parser.add_argument("--daily-report", action="store_true", help="Send daily stats report")
    parser.add_argument("--resend-show",  action="store_true", help="Resend queued show items")
    parser.add_argument("--clean-promos", action="store_true", help="Clean promotions tab")
    parser.add_argument("--setup",        action="store_true", help="Show setup instructions")
    parser.add_argument("--account",      default="all",
                        choices=list(ACCOUNTS.keys()) + ["all"])
    parser.add_argument("--max",          type=int, default=DEFAULT_MAX_EMAILS,
                        help=f"Max emails per account (default: {DEFAULT_MAX_EMAILS})")
    args = parser.parse_args()

    if args.setup:
        run_setup()
        return

    if args.digest:
        send_digest()
        return

    if args.daily_report:
        send_daily_report()
        return

    if args.resend_show:
        resend_show_items()
        return

    if args.clean_promos:
        total = 0
        accs  = list(ACCOUNTS.keys()) if args.account == "all" else [args.account]
        for acc in accs:
            total += run_promotions_cleanup(acc, max_emails=args.max, dry_run=not args.execute)
        if args.execute:
            send_telegram(TG_OWNER, f"🧹 Promotions cleaned: {total} emails deleted + unsubscribed.")
        return

    dry_run = not args.execute
    mode    = "DRY-RUN (no actions)" if dry_run else "EXECUTE"
    print(f"\n🛡️  Email Sentinel — {mode}")
    print(f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    account_keys = list(ACCOUNTS.keys()) if args.account == "all" else [args.account]
    results: dict = {}
    for acc in account_keys:
        cfg = ACCOUNTS[acc]
        if cfg.get("kind") == "imap":
            results[acc] = run_account_imap(acc, args.max, dry_run)
        else:
            results[acc] = run_account_gmail(acc, args.max, dry_run)

    total     = sum(len(v) for v in results.values())
    by_action: dict = {}
    for items in results.values():
        for item in items:
            by_action.setdefault(item["action"], []).append(item)

    print(f"\n{'='*60}")
    print(f"TOTAL: {total} emails")
    for action, items in sorted(by_action.items(), key=lambda x: PRIORITY_ORDER.get(
        min((i["priority"] for i in x[1]), key=lambda p: PRIORITY_ORDER.get(p,9)), 9
    )):
        print(f"  {ACTION_LABEL.get(action, action)}: {len(items)}")

    if not dry_run:
        send_telegram_batches(by_action)
        log_run_stats(by_action, account_keys)
        show_items = by_action.get("show_to_owner", [])
        if show_items:
            save_show_items(show_items)
        # auto-clean promotions (non-blocking)
        for acc in account_keys:
            if ACCOUNTS[acc].get("kind") != "imap":
                run_promotions_cleanup(acc, max_emails=PROMOS_MAX, dry_run=False)
    else:
        print("\nRun with --execute to apply actions.")


if __name__ == "__main__":
    main()
