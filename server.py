from __future__ import annotations

import hashlib
import hmac
import html
import json
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "site.db"
STYLES_PATH = BASE_DIR / "styles.css"
LOGO_PATH = Path("/home/yotam/.cursor/projects/home-yotam-WebSite/assets/20362c54-fe69-4f4f-a35d-28249bc5cc76-ebd49472-7226-4c48-81c2-ce39fe3758ef.png")
SESSION_COOKIE = "ailearn_session"
SESSION_DAYS = 30


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                onboarding_complete INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS onboarding_responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                question_1 TEXT NOT NULL DEFAULT '',
                question_2 TEXT NOT NULL DEFAULT '',
                question_3 TEXT NOT NULL DEFAULT '',
                question_4 TEXT NOT NULL DEFAULT '',
                question_5 TEXT NOT NULL DEFAULT '',
                question_6 TEXT NOT NULL DEFAULT '',
                learning_styles_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "onboarding_complete" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN onboarding_complete INTEGER NOT NULL DEFAULT 0")


def hash_password(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, expected_hash: str) -> bool:
    _, actual_hash = hash_password(password, salt_hex)
    return hmac.compare_digest(actual_hash, expected_hash)


def parse_cookies(raw_cookie: str | None) -> dict[str, str]:
    if not raw_cookie:
        return {}
    jar = cookies.SimpleCookie()
    jar.load(raw_cookie)
    return {name: morsel.value for name, morsel in jar.items()}


def get_user_by_session(token: str | None):
    if not token:
        return None
    with db() as conn:
        row = conn.execute(
            """
            SELECT users.id, users.email, users.name, users.onboarding_complete
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ? AND sessions.expires_at > ?
            """,
            (token, utc_now().isoformat()),
        ).fetchone()
    return row


def create_session(user_id: int) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    expires_at = utc_now() + timedelta(days=SESSION_DAYS)
    with db() as conn:
        conn.execute(
            """
            INSERT INTO sessions (user_id, token, expires_at, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, token, expires_at.isoformat(), utc_now().isoformat()),
        )
    return token, expires_at.isoformat()


def delete_session(token: str | None) -> None:
    if not token:
        return
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


def page_layout(*, title: str, body: str, user=None) -> str:
    nav = ""
    if user:
        nav = f"""
        <div class="btn-row" style="margin: 0; justify-content: flex-end; align-items: center">
          <div class="muted" style="font-weight: 700">{escape(user["email"])}</div>
          <form method="post" action="/logout" style="margin: 0">
            <button class="btn btn-ghost" type="submit">התנתקות</button>
          </form>
        </div>
        """

    return f"""<!doctype html>
<html lang="he" dir="rtl">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{escape(title)}</title>
    <link rel="stylesheet" href="/styles.css" />
  </head>
  <body>
    <div class="bg-blob" aria-hidden="true"></div>
    <main class="page">
      <header class="topbar">
        <div class="container topbar-inner">
          <a class="brand brand-link" href="/" aria-label="מעבר לעמוד הראשי">
            <img class="logo-image" src="/logo.png" alt="לוגו Lamda למדא" />
            <div class="brand-title">Lamda למדא</div>
          </a>
          {nav}
        </div>
      </header>
      {body}
    </main>
  </body>
</html>
"""


def escape(value: str) -> str:
    return html.escape(value, quote=True)


def render_login_page(message: str = "", email: str = "") -> str:
    alert = ""
    if message:
        alert = f'<div class="card panel" style="padding: 14px; margin-bottom: 14px; border-color: rgba(96, 165, 250, 0.35)"><div style="font-weight: 800">{escape(message)}</div></div>'

    body = f"""
      <div class="container center-stage">
        <section class="glass auth-card fade-in">
          <div class="auth-rows" style="padding-top: 6px">
            <div class="panel">
              <h1 class="title">ברוכים הבאים</h1>
              <p class="subtitle">
                התחברו לחשבון שלכם והמשיכו בדיוק מהמקום שבו עצרתם.
              </p>
              <div class="hero-badges" aria-hidden="true">
                <div class="badge"><div class="dot"></div><span style="font-weight: 800">זורם</span></div>
                <div class="badge"><div class="dot"></div><span style="font-weight: 800">בהיר</span></div>
                <div class="badge"><div class="dot"></div><span style="font-weight: 800">התחברות SQL</span></div>
              </div>
            </div>
            <div class="card form">
              {alert}
              <form method="post" action="/login" autocomplete="on">
                <div class="form-row">
                  <label for="email">אימייל</label>
                  <input id="email" name="email" type="email" placeholder="you@example.com" value="{escape(email)}" required />
                </div>
                <div class="form-row">
                  <label for="password">סיסמה</label>
                  <input id="password" name="password" type="password" placeholder="הכניסו סיסמה" required minlength="6" />
                </div>
                <div class="btn-row">
                  <button class="btn btn-primary" type="submit">
                    כניסה
                    <span aria-hidden="true" style="font-weight: 900"><-</span>
                  </button>
                  <a class="btn btn-ghost" href="/signup">אין לי חשבון</a>
                </div>
                <p class="hint" style="margin-top: 12px">
                  יש לכם חשבון חדש? עברו למסך ההרשמה.
                </p>
              </form>
            </div>
          </div>
        </section>
      </div>
    """
    return page_layout(title="כניסה - Lamda למדא", body=body)


def render_signup_page(message: str = "", email: str = "", name: str = "") -> str:
    alert = ""
    if message:
        alert = f'<div class="card panel" style="padding: 14px; margin-bottom: 14px; border-color: rgba(96, 165, 250, 0.35)"><div style="font-weight: 800">{escape(message)}</div></div>'

    body = f"""
      <div class="container center-stage">
        <section class="glass auth-card fade-in">
          <div class="auth-rows" style="padding-top: 6px">
            <div class="panel">
              <h1 class="title">יוצרים חשבון חדש</h1>
              <p class="subtitle">
                הצטרפו ל־Lamda למדא והתחילו במסלול שמתאים בדיוק לכם.
              </p>
              <div class="hero-badges" aria-hidden="true">
                <div class="badge"><div class="dot"></div><span style="font-weight: 800">עברית מלאה</span></div>
                <div class="badge"><div class="dot"></div><span style="font-weight: 800">התאמה אישית</span></div>
                <div class="badge"><div class="dot"></div><span style="font-weight: 800">מהיר ופשוט</span></div>
              </div>
            </div>
            <div class="card form">
              {alert}
              <form method="post" action="/signup" autocomplete="on">
                <div class="form-row">
                  <label for="name">שם מלא</label>
                  <input id="name" name="name" type="text" placeholder="השם שלכם" value="{escape(name)}" required />
                </div>
                <div class="form-row">
                  <label for="email">אימייל</label>
                  <input id="email" name="email" type="email" placeholder="you@example.com" value="{escape(email)}" required />
                </div>
                <div class="form-row">
                  <label for="password">סיסמה</label>
                  <input id="password" name="password" type="password" placeholder="בחרו סיסמה" required minlength="6" />
                </div>
                <div class="btn-row">
                  <button class="btn btn-primary" type="submit">
                    הרשמה
                    <span aria-hidden="true" style="font-weight: 900"><-</span>
                  </button>
                  <a class="btn btn-ghost" href="/login">כבר יש לי חשבון</a>
                </div>
              </form>
            </div>
          </div>
        </section>
      </div>
    """
    return page_layout(title="הרשמה - Lamda למדא", body=body)


def render_onboarding_page(user, message: str = "") -> str:
    alert = ""
    if message:
        alert = f'<div class="card panel" style="padding: 14px; margin-bottom: 18px; border-color: rgba(96, 165, 250, 0.35)"><div style="font-weight: 800">{escape(message)}</div></div>'

    body = f"""
      <div class="container center-stage">
        <section class="glass auth-card fade-in onboarding-card">
          <div class="panel">
            <h1 class="title">שלום {escape(user["name"])}!</h1>
            <p class="subtitle">
              אנחנו רוצים להכיר אותך,<br />
              מבטיחים שזה לא יקח המון זמן 🙂
            </p>
          </div>

          <div class="panel" style="padding-top: 0">
            {alert}
            <form method="post" action="/onboarding">
              <div class="card form" style="margin-bottom: 16px">
                <div class="question-title">שאלה 1</div>
                <div class="question-copy">כשכן הצלחת להבין נושא מורכב, האם זה קרה בזמן קריאת טקסט 📖 או תוך כדי צפייה בהסבר ויזואלי? 🎥</div>
                <textarea class="question-answer" name="question_1" placeholder="כתוב כאן את התשובה שלך..."></textarea>
              </div>
              <div class="questions-grid">
                <div class="card form"><div class="question-title">שאלה 2</div><div class="question-copy">כמה דקות חולפות מתחילת הלמידה עד לרגע שבו העיניים שלך עוזבות את החומר לטובת גירוי חיצוני? ⏱️</div><textarea class="question-answer" name="question_2" placeholder="כתוב כאן את התשובה שלך..."></textarea></div>
                <div class="card form"><div class="question-title">שאלה 3</div><div class="question-copy">האם הגעת לתוצאות טובות יותר לאחר פתרון 20 שאלות קצרות ⚡ או לאחר העמקה ב-3 שאלות מורכבות? 🏗️</div><textarea class="question-answer" name="question_3" placeholder="כתוב כאן את התשובה שלך..."></textarea></div>
                <div class="card form"><div class="question-title">שאלה 4</div><div class="question-copy">כדי להתקדם, האם אתה בודק את התשובה הנכונה אחרי כל סעיף 🚩 או רק בסיום המשימה כולה? 🏁</div><textarea class="question-answer" name="question_4" placeholder="כתוב כאן את התשובה שלך..."></textarea></div>
                <div class="card form"><div class="question-title">שאלה 5</div><div class="question-copy">כשלא הצלחת להבין מושג, האם עברת לנושא הבא וחזרת אליו מאוחר יותר 🔄 או שנשארת עליו עד לפיצוח? 🛠️</div><textarea class="question-answer" name="question_5" placeholder="כתוב כאן את התשובה שלך..."></textarea></div>
                <div class="card form"><div class="question-title">שאלה 6</div><div class="question-copy">האם למידה אפקטיבית עבורך כוללת שתיקיה מוחלטת בחדר 🤫 או האזנה למוזיקה/רעש רקע בזמן העבודה? 🎧</div><textarea class="question-answer" name="question_6" placeholder="כתוב כאן את התשובה שלך..."></textarea></div>
              </div>

              <div class="card form" style="margin-top: 16px">
                <div class="question-title">איך אתה מעדיף ללמוד?</div>
                <div class="btn-row" style="margin-top: 16px">
                  <a class="btn btn-primary btn-large" href="/onboarding/check">אני רוצה לבדוק!</a>
                </div>

                <div class="choice-list" style="margin-top: 18px">
                  <label class="choice-card"><input type="checkbox" name="learning_style" value="animation_videos" /> <span>סרטוני אנימציה 🎬</span></label>
                  <label class="choice-card"><input type="checkbox" name="learning_style" value="movies_series" /> <span>סרטים וסדרות 🍿</span></label>
                  <label class="choice-card"><input type="checkbox" name="learning_style" value="songs_stories" /> <span>שירים וסיפורים מוקלטים 🎧</span></label>
                  <label class="choice-card"><input type="checkbox" name="learning_style" value="reading" /> <span>ספרות (קריאה) 📚</span></label>
                  <label class="choice-card"><input type="checkbox" name="learning_style" value="games" /> <span>משחקים 🎮</span></label>
                </div>
                <div class="btn-row" style="margin-top: 18px">
                  <button class="btn btn-ghost" type="submit">המשך</button>
                </div>
              </div>
            </form>
          </div>
        </section>
      </div>
    """
    return page_layout(title="התאמה אישית - Lamda למדא", body=body, user=user)


def render_check_page(user) -> str:
    body = f"""
      <div class="container center-stage">
        <section class="glass auth-card fade-in">
          <div class="panel" style="text-align: center">
            <h1 class="title">מעולה, {escape(user["name"])}!</h1>
            <p class="subtitle">
              בחרת במסלול של בדיקה מהירה.<br />
              כאן יהיה אזור לצפייה בסרטון קצר ואז לתת לעצמך פידבק.
            </p>
            <div class="video-placeholder">
              <div class="video-icon">▶</div>
              <div class="question-title" style="margin-bottom: 6px">מקום לסרטון</div>
              <div class="hint" style="margin-top: 0">כרגע זה רק אזור תצוגה ולא סרטון פעיל.</div>
            </div>
            <div class="card form" style="margin-top: 18px; text-align: right">
              <div class="question-title">כמה למדת?</div>
              <div class="hint" style="margin-top: 0; margin-bottom: 14px">בחר דירוג בין 1 ל־5</div>
              <div class="rating-row" aria-label="דירוג למידה">
                <label class="rating-chip"><input type="radio" name="learned_rating" /> <span>1</span></label>
                <label class="rating-chip"><input type="radio" name="learned_rating" /> <span>2</span></label>
                <label class="rating-chip"><input type="radio" name="learned_rating" /> <span>3</span></label>
                <label class="rating-chip"><input type="radio" name="learned_rating" /> <span>4</span></label>
                <label class="rating-chip"><input type="radio" name="learned_rating" /> <span>5</span></label>
              </div>
            </div>
            <div class="btn-row" style="justify-content: center; margin-top: 18px">
              <form method="post" action="/onboarding/complete" style="margin: 0">
                <button class="btn btn-primary" type="submit">סיום והמשך לאתר</button>
              </form>
              <a class="btn btn-ghost" href="/onboarding">חזרה להתאמה אישית</a>
            </div>
          </div>
        </section>
      </div>
    """
    return page_layout(title="בדיקה מהירה - Lamda למדא", body=body, user=user)


def render_app_page(user) -> str:
    body = f"""
      <div class="container">
        <div class="layout">
          <aside class="sidebar">
            <div class="card panel" style="padding: 14px">
              <div class="muted" style="font-weight: 800; letter-spacing: -0.02em; margin-bottom: 10px">
                המסלול שלך
              </div>
              <nav class="nav-list" aria-label="Learning navigation">
                <div class="nav-item" data-active="true">
                  <span style="font-weight: 800">סקירה</span>
                  <span class="muted" style="font-size: 12px">ממשיכים</span>
                </div>
                <div class="nav-item">
                  <span style="font-weight: 800">קורסים</span>
                  <span class="muted" style="font-size: 12px">3</span>
                </div>
                <div class="nav-item">
                  <span style="font-weight: 800">תרגול</span>
                  <span class="muted" style="font-size: 12px">יומי</span>
                </div>
                <div class="nav-item">
                  <span style="font-weight: 800">אתגרים</span>
                  <span class="muted" style="font-size: 12px">חדש</span>
                </div>
              </nav>
            </div>
          </aside>

          <section style="min-width: 0">
            <div class="panel-header">
              <div>
                <div class="title" style="font-size: 26px">כיף לראות אותך, {escape(user["name"])}.</div>
                <div class="subtitle">אתם מחוברים עם סשן אמיתי שנשמר ב־SQLite.</div>
              </div>
            </div>

            <div class="section" style="padding-top: 14px">
              <div class="grid-2 fade-in">
                <div class="kpi"><strong>7</strong><span>רצף ימים</span></div>
                <div class="kpi"><strong>420</strong><span>נקודות למידה</span></div>
              </div>

              <div class="lesson-wrap" style="margin-top: 16px">
                <div class="card panel card-strong fade-in">
                  <div class="panel-header" style="margin-bottom: 12px">
                    <div>
                      <h2 class="lesson-title">השיעור הבא: "כתיבת פרומפטים שבאמת עובדים"</h2>
                      <div class="lesson-meta">6 דקות | מיני שיעור + שני תרגילים קצרים</div>
                    </div>
                    <div style="min-width: 160px; text-align: right">
                      <div class="muted" style="font-size: 12px; font-weight: 900">התקדמות</div>
                      <div class="progress" aria-label="Lesson progress"><div style="--w: 48%"></div></div>
                      <div class="muted" style="font-size: 12px; margin-top: 6px; font-weight: 800">48% הושלם</div>
                    </div>
                  </div>

                  <div style="display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 14px">
                    <span class="badge" style="background: rgba(255, 255, 255, 0.72)">ידידותי למתחילים</span>
                    <span class="badge" style="background: rgba(255, 255, 255, 0.72)">דוגמאות מעשיות</span>
                    <span class="badge" style="background: rgba(255, 255, 255, 0.72)">פידבק מיידי</span>
                  </div>

                  <div class="btn-row" style="margin-top: 8px">
                    <button class="btn btn-primary" type="button"><- המשך לשיעור</button>
                    <button class="btn btn-ghost" type="button">שמירה לאחר כך</button>
                  </div>
                </div>

                <div class="card panel fade-in">
                  <div class="muted" style="font-weight: 900; letter-spacing: -0.02em">פרטי חשבון</div>
                  <div style="height: 12px"></div>
                  <div class="kpi">
                    <strong>{escape(user["name"])}</strong>
                    <span>{escape(user["email"])}</span>
                  </div>
                  <p class="hint" style="margin: 14px 0 0 0">
                    העמוד הזה מגיע עכשיו מהשרת בפייתון, וההתחברות נשמרת עם SQL ו־cookies.
                  </p>
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>
    """
    return page_layout(title="Lamda למדא", body=body, user=user)


class AIWebsiteHandler(BaseHTTPRequestHandler):
    server_version = "AILearningServer/1.0"

    def do_HEAD(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            user = self.current_user()
            if user:
                return self.redirect("/app")
            return self.redirect("/login")

        if path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            return

        if path == "/signup":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            return

        if path == "/onboarding":
            if not self.current_user():
                return self.redirect("/login?" + urlencode({"message": "יש להתחבר קודם"}))
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            return

        if path == "/onboarding/check":
            if not self.current_user():
                return self.redirect("/login?" + urlencode({"message": "יש להתחבר קודם"}))
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            return

        if path == "/app":
            user = self.current_user()
            if not user:
                return self.redirect("/login?" + urlencode({"message": "יש להתחבר קודם"}))
            if not user["onboarding_complete"]:
                return self.redirect("/onboarding")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            return

        if path == "/styles.css":
            self.send_response(200 if STYLES_PATH.exists() else 404)
            self.send_header("Content-Type", "text/css; charset=utf-8")
            self.end_headers()
            return

        if path == "/logo.png":
            self.send_response(200 if LOGO_PATH.exists() else 404)
            self.send_header("Content-Type", "image/png")
            self.end_headers()
            return

        self.send_error(404, "Page not found")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/styles.css":
            return self.serve_styles()

        if path == "/logo.png":
            return self.serve_logo()

        if path == "/":
            user = self.current_user()
            if user:
                return self.redirect("/app")
            return self.redirect("/login")

        if path == "/login":
            if self.current_user():
                return self.redirect("/app")
            params = parse_qs(parsed.query)
            message = params.get("message", [""])[0]
            email = params.get("email", [""])[0]
            return self.send_html(render_login_page(message=message, email=email))

        if path == "/signup":
            if self.current_user():
                return self.redirect("/app")
            params = parse_qs(parsed.query)
            message = params.get("message", [""])[0]
            email = params.get("email", [""])[0]
            name = params.get("name", [""])[0]
            return self.send_html(render_signup_page(message=message, email=email, name=name))

        if path == "/onboarding":
            user = self.current_user()
            if not user:
                return self.redirect("/login?" + urlencode({"message": "יש להתחבר קודם"}))
            if user["onboarding_complete"]:
                return self.redirect("/app")
            params = parse_qs(parsed.query)
            message = params.get("message", [""])[0]
            return self.send_html(render_onboarding_page(user, message=message))

        if path == "/onboarding/check":
            user = self.current_user()
            if not user:
                return self.redirect("/login?" + urlencode({"message": "יש להתחבר קודם"}))
            return self.send_html(render_check_page(user))

        if path == "/app":
            user = self.current_user()
            if not user:
                return self.redirect("/login?" + urlencode({"message": "יש להתחבר קודם"}))
            if not user["onboarding_complete"]:
                return self.redirect("/onboarding")
            return self.send_html(render_app_page(user))

        self.send_error(404, "Page not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/login":
            return self.handle_login()

        if parsed.path == "/signup":
            return self.handle_signup()

        if parsed.path == "/onboarding":
            return self.handle_onboarding()

        if parsed.path == "/onboarding/complete":
            return self.complete_onboarding()

        if parsed.path == "/logout":
            token = parse_cookies(self.headers.get("Cookie")).get(SESSION_COOKIE)
            delete_session(token)
            self.send_response(303)
            self.send_header("Location", "/login?" + urlencode({"message": "התנתקת בהצלחה"}))
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
            )
            self.end_headers()
            return

        self.send_error(404, "Page not found")

    def current_user(self):
        token = parse_cookies(self.headers.get("Cookie")).get(SESSION_COOKIE)
        return get_user_by_session(token)

    def handle_login(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length).decode("utf-8")
        form = parse_qs(raw)
        email = form.get("email", [""])[0].strip().lower()
        password = form.get("password", [""])[0]
        if not email or "@" not in email:
            return self.redirect("/login?" + urlencode({"message": "יש להזין אימייל תקין"}))
        if len(password) < 6:
            return self.redirect(
                "/login?" + urlencode({"message": "הסיסמה חייבת להכיל לפחות 6 תווים", "email": email})
            )

        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

            if not user:
                return self.redirect("/login?" + urlencode({"message": "לא נמצא חשבון עם האימייל הזה", "email": email}))
            if not verify_password(password, user["password_salt"], user["password_hash"]):
                return self.redirect("/login?" + urlencode({"message": "סיסמה שגויה", "email": email}))
            user_id = user["id"]

        token, _ = create_session(user_id)
        self.send_response(303)
        self.send_header("Location", "/onboarding" if not user["onboarding_complete"] else "/app")
        self.send_header(
            "Set-Cookie",
            f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_DAYS * 24 * 60 * 60}",
        )
        self.end_headers()

    def handle_signup(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length).decode("utf-8")
        form = parse_qs(raw)
        name = form.get("name", [""])[0].strip()
        email = form.get("email", [""])[0].strip().lower()
        password = form.get("password", [""])[0]

        if not name:
            return self.redirect("/signup?" + urlencode({"message": "יש להזין שם מלא", "email": email}))
        if not email or "@" not in email:
            return self.redirect("/signup?" + urlencode({"message": "יש להזין אימייל תקין", "name": name}))
        if len(password) < 6:
            return self.redirect(
                "/signup?" + urlencode({"message": "הסיסמה חייבת להכיל לפחות 6 תווים", "email": email, "name": name})
            )

        with db() as conn:
            existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if existing:
                return self.redirect(
                    "/signup?" + urlencode({"message": "כבר קיים חשבון עם האימייל הזה", "email": email, "name": name})
                )

            salt_hex, password_hash = hash_password(password)
            cursor = conn.execute(
                """
                INSERT INTO users (email, name, password_salt, password_hash, onboarding_complete, created_at)
                VALUES (?, ?, ?, ?, 0, ?)
                """,
                (email, name, salt_hex, password_hash, utc_now().isoformat()),
            )
            user_id = cursor.lastrowid

        token, _ = create_session(user_id)
        self.send_response(303)
        self.send_header("Location", "/onboarding")
        self.send_header(
            "Set-Cookie",
            f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_DAYS * 24 * 60 * 60}",
        )
        self.end_headers()

    def handle_onboarding(self) -> None:
        user = self.current_user()
        if not user:
            return self.redirect("/login?" + urlencode({"message": "יש להתחבר קודם"}))
        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length).decode("utf-8")
        form = parse_qs(raw)

        responses = {
            "question_1": form.get("question_1", [""])[0].strip(),
            "question_2": form.get("question_2", [""])[0].strip(),
            "question_3": form.get("question_3", [""])[0].strip(),
            "question_4": form.get("question_4", [""])[0].strip(),
            "question_5": form.get("question_5", [""])[0].strip(),
            "question_6": form.get("question_6", [""])[0].strip(),
        }
        learning_styles = [value.strip() for value in form.get("learning_style", []) if value.strip()]

        now = utc_now().isoformat()
        with db() as conn:
            conn.execute(
                """
                INSERT INTO onboarding_responses (
                    user_id, question_1, question_2, question_3, question_4, question_5, question_6,
                    learning_styles_json, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    question_1=excluded.question_1,
                    question_2=excluded.question_2,
                    question_3=excluded.question_3,
                    question_4=excluded.question_4,
                    question_5=excluded.question_5,
                    question_6=excluded.question_6,
                    learning_styles_json=excluded.learning_styles_json,
                    updated_at=excluded.updated_at
                """,
                (
                    user["id"],
                    responses["question_1"],
                    responses["question_2"],
                    responses["question_3"],
                    responses["question_4"],
                    responses["question_5"],
                    responses["question_6"],
                    json.dumps(learning_styles, ensure_ascii=False),
                    now,
                    now,
                ),
            )
        return self.complete_onboarding(redirect_to="/app")

    def complete_onboarding(self, redirect_to: str = "/app") -> None:
        user = self.current_user()
        if not user:
            return self.redirect("/login?" + urlencode({"message": "יש להתחבר קודם"}))
        with db() as conn:
            conn.execute("UPDATE users SET onboarding_complete = 1 WHERE id = ?", (user["id"],))
        self.redirect(redirect_to)

    def serve_styles(self) -> None:
        if not STYLES_PATH.exists():
            return self.send_error(404, "styles.css not found")
        payload = STYLES_PATH.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/css; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def serve_logo(self) -> None:
        if not LOGO_PATH.exists():
            return self.send_error(404, "logo.png not found")
        payload = LOGO_PATH.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_html(self, markup: str, status: int = 200) -> None:
        payload = markup.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.end_headers()


def run() -> None:
    init_db()
    host = "0.0.0.0"
    port = 8080
    server = ThreadingHTTPServer((host, port), AIWebsiteHandler)
    print(f"Serving Lamda למדא on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
