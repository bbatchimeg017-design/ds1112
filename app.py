import json
import os
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import bcrypt
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)


def load_env_file():
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        return

    with open(env_path, encoding="utf-8") as env_file:
        for line in env_file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            value = value.strip().strip("\"'")
            os.environ.setdefault(name.strip(), value)


class SupabaseError(Exception):
    pass


EMAIL_PATTERN = re.compile(r"[^@\s'\"<>(),;]+@[^@\s'\"<>(),;]+\.[^@\s'\"<>(),;]+")

# PostgreSQL error codes -> plain-language messages
DB_ERROR_MESSAGES = {
    "23502": "Заавал бөглөх талбар хоосон байна.",
    "23505": "Ийм мэдээлэл аль хэдийн бүртгэлтэй байна.",
    "23514": "Сонгосон утгыг Supabase хүлээж авсангүй (жишээ нь төлөв).",
    "22P02": "Утгын хэлбэр буруу байна (тоо, огноо гэх мэт).",
    "22007": "Огноо, цагийн хэлбэр буруу байна.",
}


def supabase_request(method, table, params, body=None):
    base_url = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    api_key = os.environ.get("SUPABASE_SECRET_KEY", "").strip()
    if not base_url or not api_key:
        raise SupabaseError(
            "SUPABASE_URL болон SUPABASE_SECRET_KEY утгыг .env файлд оруулна уу."
        )
    if api_key.startswith("sb_publishable_"):
        raise SupabaseError(
            ".env дотор publishable түлхүүр байна. Сервер талд ашиглах Supabase secret түлхүүрээр солино уу."
        )

    query = urllib.parse.urlencode(params)
    url = f"{base_url}/rest/v1/{table}?{query}"
    headers = {
        "apikey": api_key,
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }
    data = None
    if method != "GET":
        headers["Prefer"] = "return=representation"
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            result = json.loads(response.read().decode("utf-8") or "[]")
    except urllib.error.HTTPError as error:
        if error.code in (401, 403):
            raise SupabaseError(
                "Supabase түлхүүр хүснэгт унших эрхгүй байна. Secret түлхүүр болон RLS тохиргоог шалгана уу."
            ) from None
        if error.code == 404:
            raise SupabaseError(
                f"Supabase дээр '{table}' хүснэгт олдсонгүй. "
                "SQL файлаа SQL Editor-т ажиллуулсан эсэхээ шалгана уу."
            ) from None
        if error.code in (400, 409) and method != "GET":
            try:
                db_code = json.loads(error.read().decode("utf-8")).get("code", "")
            except (ValueError, UnicodeDecodeError, AttributeError):
                db_code = ""
            reason = DB_ERROR_MESSAGES.get(db_code, "Оруулсан утгууд зөв эсэхийг шалгана уу.")
            raise SupabaseError(f"Supabase хадгалж чадсангүй. {reason}") from None
        raise SupabaseError(
            f"Supabase хүсэлт амжилтгүй боллоо (HTTP {error.code})."
        ) from None
    except urllib.error.URLError:
        raise SupabaseError(
            "Supabase-тэй холбогдож чадсангүй. Хаяг болон интернет холболтоо шалгана уу."
        ) from None
    except (UnicodeDecodeError, ValueError):
        raise SupabaseError("Supabase-аас уншигдахгүй хариу ирлээ.") from None

    if not isinstance(result, list):
        raise SupabaseError("Supabase-аас хүлээгдээгүй хариу ирлээ.")
    return result


def supabase_get(table, params):
    return supabase_request("GET", table, params)


load_env_file()
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "true",
)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; img-src 'self' data:; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    return response


def csrf_token():
    token = session.get("csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def valid_csrf():
    submitted = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    return bool(submitted and expected and secrets.compare_digest(submitted, expected))


@app.route("/", methods=["GET", "POST"])
def login():
    if session.get("user_email"):
        return redirect(url_for("dashboard"))

    error = None
    email = ""
    if request.method == "POST":
        if not valid_csrf():
            return "Хүсэлт баталгаажсангүй. Хуудсаа дахин ачаална уу.", 400

        email = request.form.get("email", "").strip()[:200]
        password = request.form.get("password", "")
        if not email or not password:
            error = "И-мэйл болон нууц үгээ оруулна уу."
        elif not EMAIL_PATTERN.fullmatch(email):
            # Never send malformed input to Supabase; answer like a wrong login.
            error = "И-мэйл эсвэл нууц үг буруу байна."
        else:
            try:
                users = supabase_get(
                    "users",
                    {
                        "select": "email,password_hash",
                        "email": f"eq.{email}",
                        "limit": "1",
                    },
                )
            except SupabaseError as exc:
                error = str(exc)
            else:
                if users:
                    stored_hash = users[0].get("password_hash", "")
                    try:
                        password_matches = bcrypt.checkpw(
                            password.encode("utf-8"),
                            stored_hash.encode("utf-8"),
                        )
                    except (ValueError, TypeError):
                        password_matches = False
                    if password_matches:
                        session.clear()
                        session["user_email"] = users[0]["email"]
                        session["csrf_token"] = secrets.token_urlsafe(32)
                        return redirect(url_for("dashboard"))
                if error is None:
                    error = "И-мэйл эсвэл нууц үг буруу байна."

    return render_template(
        "login.html", error=error, email=email, csrf_token=csrf_token()
    )


UB_TIME = timezone(timedelta(hours=8))

# Must match the check constraint on the live `bookings` table
# (pending / confirmed / cancelled — "completed" is rejected by Supabase).
BOOKING_STATUS = {
    "pending": "Хүлээгдэж буй",
    "confirmed": "Баталгаажсан",
    "cancelled": "Цуцалсан",
}

CONTENT_STATUS = {
    "draft": "Ноорог",
    "published": "Нийтэлсэн",
}

STAFF_STATUS = {
    "active": "Ажиллаж буй",
    "leave": "Чөлөөтэй",
    "inactive": "Гарсан",
}

# Each menu that stores data in Supabase. The same add / edit / delete /
# search code works for all of them, driven by this description.
RESOURCES = {
    "content": {
        "table": "content_drafts",
        "list_endpoint": "dashboard",
        "menu": "content",
        "singular": "пост",
        "label_field": "title",
        "order": "created_at.desc",
        "search": ["title", "content"],
        "fields": [
            {"name": "title", "label": "Гарчиг", "type": "text", "required": True},
            {"name": "content", "label": "Текст", "type": "textarea", "required": True},
            {"name": "status", "label": "Төлөв", "type": "select",
             "options": CONTENT_STATUS, "required": True, "default": "draft"},
        ],
    },
    "bookings": {
        "table": "bookings",
        "list_endpoint": "bookings",
        "menu": "bookings",
        "singular": "захиалга",
        "label_field": "customer_name",
        "order": "booking_at.asc",
        "search": ["customer_name", "customer_email"],
        "fields": [
            {"name": "customer_name", "label": "Үйлчлүүлэгчийн нэр", "type": "text",
             "required": True},
            {"name": "customer_email", "label": "И-мэйл", "type": "email",
             "required": True},
            {"name": "booking_at", "label": "Огноо, цаг", "type": "datetime",
             "required": True},
            {"name": "guest_count", "label": "Хүний тоо", "type": "number",
             "required": True, "min": 1, "default": "1"},
            {"name": "status", "label": "Төлөв", "type": "select",
             "options": BOOKING_STATUS, "required": True, "default": "pending"},
        ],
    },
    "staff": {
        "table": "staff",
        "list_endpoint": "staff",
        "menu": "staff",
        "singular": "ажилтан",
        "label_field": "full_name",
        "order": "id.asc",
        "search": ["full_name", "position", "phone", "email"],
        "fields": [
            {"name": "full_name", "label": "Овог нэр", "type": "text", "required": True},
            {"name": "position", "label": "Албан тушаал", "type": "text",
             "required": True},
            {"name": "phone", "label": "Утас", "type": "tel"},
            {"name": "email", "label": "И-мэйл", "type": "email"},
            {"name": "status", "label": "Төлөв", "type": "select",
             "options": STAFF_STATUS, "required": True, "default": "active"},
            {"name": "hired_on", "label": "Ажилд орсон огноо", "type": "date"},
        ],
    },
}


PROJECT_PHOTOS = [
    ("mcu-tower", "MCU Tower"),
    ("vega-city", "Vega City"),
    ("gerlug-palace", "Gerlug Palace"),
    ("casa-da-vinci", "Casa Da Vinci"),
    ("garden-city-2", "Garden City 2"),
    ("vip-residence-3", "VIP Residence 3"),
    ("altan-joloo-tower", "Altan Joloo Tower"),
    ("cedar-city", "Cedar City"),
    ("gerlug-vista", "Gerlug Vista"),
    ("villa-verde", "Villa Verde"),
    ("green-hill-villa", "Green Hill Villa"),
    ("barilgachin-tuv", "Барилгачин худалдааны төв"),
]

FACEBOOK_POSTS = [
    {
        "gallery": [
            {"image": f"projects/{slug}.jpg", "name": name}
            for slug, name in PROJECT_PHOTOS
        ],
        "date": "2026-11-12",
        "status": "Бэлэн",
        "caption": (
            "🏗️ БИДНИЙ ХИЙСЭН ТӨСЛҮҮД\n\n"
            "2020 оноос хойш бид 60 гаруй төсөл дээр 390,000 м² гаруй "
            "бетон цутгалт хийлээ. Тэдгээрээс онцлох хэдэн төслөө "
            "хүргэж байна 👇\n\n"
            "Танай дараагийн төслийг хамтдаа бүтээе! 🤝\n"
            "📞 9907-3739 · 9908-8497"
        ),
    },
    {
        "image": "winter-poster.png",
        "alt": "Оны сүүлийн хөнгөлөлттэй захиалга — DS Construction",
        "date": "2026-11-12",
        "status": "Бэлэн",
        "caption": (
            "❄️ ОНЫ СҮҮЛИЙН ХӨНГӨЛӨЛТТЭЙ ЗАХИАЛГА ❄️\n\n"
            "Бетон шал цутгалт, өнгөлгөөний ажлаа оны сүүлийн "
            "хөнгөлөлттэй үнээр захиалаарай. Захиалгын хуваарь хязгаартай!\n\n"
            "📞 9965-6665\n"
            "📍 Хан-Уул дүүрэг, Мөнх Тауэр, 504 тоот"
        ),
    },
]


INSTAGRAM_HASHTAGS = (
    "#DSConstruction #PrecisionConcreteSolution #бетон #бетонцутгалт "
    "#барилга #Улаанбаатар"
)

INSTAGRAM_POSTS = [
    {
        "shape": "landscape",
        "slides": [
            {"image": f"projects/{slug}.jpg", "alt": name}
            for slug, name in PROJECT_PHOTOS
        ],
        "date": "2026-11-12",
        "status": "Бэлэн",
        "caption": (
            "🏗️ Бидний хийсэн төслүүд\n"
            "2020 оноос хойш 60+ төсөл, 390,000+ м² бетон цутгалт.\n"
            "👉 Зургуудыг гүйлгэж үзээрэй\n\n"
            "📞 9907-3739 · 9908-8497"
        ),
        "hashtags": INSTAGRAM_HASHTAGS + " #төсөл",
    },
    {
        "shape": "portrait",
        "slides": [
            {
                "image": "winter-poster.png",
                "alt": "Оны сүүлийн хөнгөлөлттэй захиалга — DS Construction",
            }
        ],
        "date": "2026-11-12",
        "status": "Бэлэн",
        "caption": (
            "❄️ Оны сүүлийн хөнгөлөлттэй захиалга ❄️\n"
            "Бетон шал цутгалт, өнгөлгөөний ажлаа хөнгөлөлттэй үнээр "
            "захиалаарай. Захиалгын хуваарь хязгаартай!\n\n"
            "📞 9965-6665"
        ),
        "hashtags": INSTAGRAM_HASHTAGS + " #хямдрал #өвөл",
    },
]


def format_datetime(value):
    if not value:
        return ""
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    return moment.astimezone(UB_TIME).strftime("%Y-%m-%d %H:%M")


app.jinja_env.filters["ubtime"] = format_datetime


def render_page(template, active, **context):
    return render_template(
        template,
        active=active,
        email=session["user_email"],
        csrf_token=csrf_token(),
        **context,
    )


def to_datetime_input(value):
    """Supabase timestamp -> value for <input type="datetime-local"> (UB time)."""
    if not value:
        return ""
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return ""
    return moment.astimezone(UB_TIME).strftime("%Y-%m-%dT%H:%M")


def search_filter(columns, query):
    """Build a PostgREST `or` filter that matches any column (case-insensitive)."""
    cleaned = re.sub(r'[,()"\\*%]', " ", query).strip()
    if not cleaned:
        return {}
    parts = ",".join(f'{column}.ilike."*{cleaned}*"' for column in columns)
    return {"or": f"({parts})"}


def list_resource(name):
    """Rows for a list page, filtered by the ?q= search box."""
    config = RESOURCES[name]
    query = request.args.get("q", "").strip()[:100]
    params = {"select": "*", "order": config["order"]}
    params.update(search_filter(config["search"], query))
    try:
        return supabase_get(config["table"], params), query, None
    except SupabaseError as exc:
        return [], query, str(exc)


def form_values(config, row=None):
    values = {}
    for field in config["fields"]:
        if row is None:
            values[field["name"]] = field.get("default", "")
            continue
        value = row.get(field["name"])
        if field["type"] == "datetime":
            value = to_datetime_input(value)
        values[field["name"]] = "" if value is None else str(value)
    return values


def parse_form(config):
    """Validate submitted form. Returns (values_for_redisplay, payload, errors)."""
    values, payload, errors = {}, {}, {}
    for field in config["fields"]:
        name, label, kind = field["name"], field["label"], field["type"]
        raw = request.form.get(name, "").strip()
        values[name] = raw

        if not raw:
            if field.get("required"):
                errors[name] = f"«{label}» талбарыг бөглөнө үү."
            payload[name] = None
            continue

        limit = 5000 if kind == "textarea" else 200
        if len(raw) > limit:
            errors[name] = f"«{label}» хэт урт байна ({limit} тэмдэгтээс ихгүй)."
        elif kind == "select" and raw not in field["options"]:
            errors[name] = f"«{label}» талбарын утга буруу байна."
        elif kind == "email" and not EMAIL_PATTERN.fullmatch(raw):
            errors[name] = "И-мэйл хаяг буруу байна."
        elif kind == "number":
            try:
                number = int(raw)
            except ValueError:
                errors[name] = f"«{label}» бүхэл тоо байх ёстой."
            else:
                if number < field.get("min", number):
                    errors[name] = f"«{label}» {field['min']}-ээс багагүй байна."
                payload[name] = number
            continue
        elif kind == "datetime":
            try:
                moment = datetime.strptime(raw, "%Y-%m-%dT%H:%M")
            except ValueError:
                errors[name] = f"«{label}» огноо, цаг буруу байна."
            else:
                payload[name] = moment.replace(tzinfo=UB_TIME).isoformat()
            continue
        elif kind == "date":
            try:
                datetime.strptime(raw, "%Y-%m-%d")
            except ValueError:
                errors[name] = f"«{label}» огноо буруу байна."
        payload[name] = raw
    return values, payload, errors


def get_config(resource):
    config = RESOURCES.get(resource)
    if config is None:
        abort(404)
    return config


def fetch_item(config, item_id):
    rows = supabase_get(
        config["table"], {"select": "*", "id": f"eq.{item_id}", "limit": "1"}
    )
    return rows[0] if rows else None


def back_to_list(config):
    return redirect(url_for(config["list_endpoint"]))


@app.route("/dashboard")
def dashboard():
    if not session.get("user_email"):
        return redirect(url_for("login"))
    rows, query, error = list_resource("content")
    return render_page(
        "dashboard.html", "content",
        posts=rows, query=query, error=error, status_labels=CONTENT_STATUS,
    )


@app.route("/staff")
def staff():
    if not session.get("user_email"):
        return redirect(url_for("login"))
    rows, query, error = list_resource("staff")
    return render_page(
        "staff.html", "staff",
        staff=rows, query=query, error=error, status_labels=STAFF_STATUS,
    )


@app.route("/<resource>/new", methods=["GET", "POST"])
def create_item(resource):
    if not session.get("user_email"):
        return redirect(url_for("login"))
    config = get_config(resource)
    values, errors, error = form_values(config), {}, None

    if request.method == "POST":
        if not valid_csrf():
            return "Хүсэлт баталгаажсангүй. Хуудсаа дахин ачаална уу.", 400
        values, payload, errors = parse_form(config)
        if not errors:
            try:
                supabase_request("POST", config["table"], {"select": "id"}, payload)
            except SupabaseError as exc:
                error = str(exc)
            else:
                flash(f"Шинэ {config['singular']} нэмэгдлээ.", "success")
                return back_to_list(config)

    return render_page(
        "form.html", config["menu"], config=config, resource=resource,
        values=values, errors=errors, error=error, item_id=None,
    )


@app.route("/<resource>/<int:item_id>/edit", methods=["GET", "POST"])
def edit_item(resource, item_id):
    if not session.get("user_email"):
        return redirect(url_for("login"))
    config = get_config(resource)
    errors, error = {}, None

    if request.method == "POST":
        if not valid_csrf():
            return "Хүсэлт баталгаажсангүй. Хуудсаа дахин ачаална уу.", 400
        values, payload, errors = parse_form(config)
        if not errors:
            try:
                updated = supabase_request(
                    "PATCH", config["table"],
                    {"id": f"eq.{item_id}", "select": "id"}, payload,
                )
            except SupabaseError as exc:
                error = str(exc)
            else:
                if updated:
                    flash(f"{config['singular'].capitalize()} засагдлаа.", "success")
                else:
                    flash(f"Ийм {config['singular']} олдсонгүй.", "error")
                return back_to_list(config)
    else:
        try:
            row = fetch_item(config, item_id)
        except SupabaseError as exc:
            flash(str(exc), "error")
            return back_to_list(config)
        if row is None:
            flash(f"Ийм {config['singular']} олдсонгүй.", "error")
            return back_to_list(config)
        values = form_values(config, row)

    return render_page(
        "form.html", config["menu"], config=config, resource=resource,
        values=values, errors=errors, error=error, item_id=item_id,
    )


@app.route("/<resource>/<int:item_id>/delete", methods=["GET", "POST"])
def delete_item(resource, item_id):
    if not session.get("user_email"):
        return redirect(url_for("login"))
    config = get_config(resource)

    if request.method == "POST":
        if not valid_csrf():
            return "Хүсэлт баталгаажсангүй. Хуудсаа дахин ачаална уу.", 400
        try:
            deleted = supabase_request(
                "DELETE", config["table"], {"id": f"eq.{item_id}", "select": "id"}
            )
        except SupabaseError as exc:
            flash(str(exc), "error")
        else:
            if deleted:
                flash(f"{config['singular'].capitalize()} устгагдлаа.", "success")
            else:
                flash(f"Ийм {config['singular']} олдсонгүй.", "error")
        return back_to_list(config)

    # GET: ask before deleting
    try:
        row = fetch_item(config, item_id)
    except SupabaseError as exc:
        flash(str(exc), "error")
        return back_to_list(config)
    if row is None:
        flash(f"Ийм {config['singular']} олдсонгүй.", "error")
        return back_to_list(config)

    return render_page(
        "confirm_delete.html", config["menu"], config=config, resource=resource,
        item_id=item_id, label=row.get(config["label_field"]) or f"#{item_id}",
    )


@app.route("/facebook")
def facebook():
    if not session.get("user_email"):
        return redirect(url_for("login"))
    return render_page("facebook.html", "facebook", posts=FACEBOOK_POSTS)


@app.route("/instagram")
def instagram():
    if not session.get("user_email"):
        return redirect(url_for("login"))
    return render_page("instagram.html", "instagram", posts=INSTAGRAM_POSTS)


@app.route("/chat")
def chat():
    if not session.get("user_email"):
        return redirect(url_for("login"))
    return render_page("coming_soon.html", "chat", page_title="Чат")


@app.route("/bookings")
def bookings():
    if not session.get("user_email"):
        return redirect(url_for("login"))

    rows, query, error = list_resource("bookings")
    return render_page(
        "bookings.html", "bookings",
        bookings=rows, query=query, error=error, status_labels=BOOKING_STATUS,
    )


@app.post("/logout")
def logout():
    if not valid_csrf():
        return "Хүсэлт баталгаажсангүй. Хуудсаа дахин ачаална уу.", 400
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
