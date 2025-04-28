import os
from flask import (
    Flask,
    render_template,
    request,
    url_for,
    flash,
    redirect,
    abort,
    jsonify,
)
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error
from datetime import datetime
import math
import re
import random
import string
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)

load_dotenv()

app = Flask(__name__, static_folder=".", static_url_path="")


app.config["SECRET_KEY"] = os.getenv(
    "FLASK_SECRET_KEY", "dev-secret-key-should-be-changed"
)


app.template_folder = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "templates"
)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"


ADMIN_USERNAME_STORE = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_STORE = os.getenv("ADMIN_PASSWORD")


API_KEY_STORE = os.getenv("API_SECRET_KEY")


class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

    @staticmethod
    def get(user_id):

        if user_id == "1" and ADMIN_PASSWORD_STORE:
            return User(id="1", username=ADMIN_USERNAME_STORE)
        return None

    @staticmethod
    def validate(username, password):

        if username == ADMIN_USERNAME_STORE and ADMIN_PASSWORD_STORE:
            if ADMIN_PASSWORD_STORE == password:
                return User.get("1")
        return None


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


VALID_SORT_COLUMNS = {"keyword", "url", "title", "timestamp", "clicks"}
VALID_SEARCH_COLUMNS = {"keyword", "url", "title", "ip"}
DEFAULT_SORT_BY = "timestamp"
DEFAULT_SORT_ORDER = "DESC"
DEFAULT_PER_PAGE = 15


def get_db_connection():
    """Establishes a connection to the database."""
    try:
        conn = mysql.connector.connect(
            host=os.getenv("DB_HOST", "localhost"),
            database=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            port=int(os.getenv("DB_PORT", 3306)),
        )
        if conn.is_connected():

            return conn
    except Error as e:
        print(f"Error connecting to MySQL Database: {e}")

        return None
    except ValueError:
        print(f"Error: Invalid DB_PORT value in .env. Must be an integer.")
        return None


def simple_number_format(value):
    """Basic number format filter."""
    try:
        if isinstance(value, int):
            return f"{value:,}"
        return str(value)
    except (ValueError, TypeError):
        return str(value)


def format_datetime(value, format="%Y-%m-%d %H:%M"):
    """Formats a datetime object or timestamp string."""
    if isinstance(value, datetime):
        return value.strftime(format)
    try:

        dt_object = datetime.fromisoformat(str(value))
        return dt_object.strftime(format)
    except (ValueError, TypeError):
        return str(value)


def generate_sort_url(column_name, current_sort_by, current_sort_order, current_args):
    """Generates URL for sorting table columns, preserving other query params."""
    args = current_args.copy()
    args["sort_by"] = column_name

    if current_sort_by == column_name and current_sort_order == "ASC":
        args["sort_order"] = "DESC"
    else:
        args["sort_order"] = "ASC"

    return url_for("admin_index", **args)


def generate_page_url(page_num, current_args):
    """Generates URL for a specific page, preserving other query params."""
    args = current_args.copy()
    args["page"] = page_num
    return url_for("admin_index", **args)


app.jinja_env.filters["numberformat"] = simple_number_format
app.jinja_env.filters["dateformat"] = format_datetime
app.add_template_global(generate_sort_url, name="sort_url")
app.add_template_global(generate_page_url, name="page_url")


def get_admin_index_data(args):
    """Fetches data required for the admin index page, handling filters and pagination."""
    conn = get_db_connection()
    if not conn:

        return {
            "page_title": "YOURLS Admin - DB Error",
            "total_urls": 0,
            "total_clicks": 0,
            "display_on_page": 0,
            "max_on_page": 0,
            "total_items": 0,
            "total_items_clicks": None,
            "search_sentence": "Database connection error.",
            "links": [],
            "page": 1,
            "perpage": DEFAULT_PER_PAGE,
            "total_pages": 1,
            "sort_by": DEFAULT_SORT_BY,
            "sort_order": DEFAULT_SORT_ORDER,
            "search": "",
            "search_in": "keyword",
            "filter": "",
        }

    context = {}
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)

        try:
            page = int(args.get("page", "1"))
            if page < 1:
                page = 1
        except ValueError:
            page = 1

        try:
            perpage = int(args.get("perpage", str(DEFAULT_PER_PAGE)))
            if perpage < 1:
                perpage = DEFAULT_PER_PAGE
        except ValueError:
            perpage = DEFAULT_PER_PAGE

        sort_by = args.get("sort_by", DEFAULT_SORT_BY).lower()
        if sort_by not in VALID_SORT_COLUMNS:
            sort_by = DEFAULT_SORT_BY

        sort_order = args.get("sort_order", DEFAULT_SORT_ORDER).upper()
        if sort_order not in {"ASC", "DESC"}:
            sort_order = DEFAULT_SORT_ORDER

        search = args.get("search", "").strip()
        search_in = args.get("search_in", "keyword").lower()

        filter_param = args.get("filter", "")

        click_filter = args.get("click_filter", "more").lower()
        if click_filter not in {"more", "less"}:
            click_filter = "more"
        try:
            click_limit_str = args.get("click_limit", "").strip()
            click_limit = int(click_limit_str) if click_limit_str else None
        except ValueError:
            click_limit = None

        date_filter = args.get("date_filter", "").lower()

        date_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}$")
        date_first_str = args.get("date_first", "").strip()
        date_first = date_first_str if date_pattern.match(date_first_str) else None
        date_second_str = args.get("date_second", "").strip()
        date_second = date_second_str if date_pattern.match(date_second_str) else None

        where_clauses = []
        bind_params = {}
        search_sentence = ""

        if search:
            search_term_like = f"%{search}%"
            if search_in == "all":
                where_clauses.append(
                    "CONCAT_WS('', keyword, url, title, ip) LIKE %(search)s"
                )
                bind_params["search"] = search_term_like
                search_sentence = f'Searching for "{search}" in all fields.'
            elif search_in in VALID_SEARCH_COLUMNS:

                where_clauses.append(f"`{search_in}` LIKE %(search)s")
                bind_params["search"] = search_term_like
                search_sentence = f'Searching for "{search}" in {search_in}.'
            else:

                where_clauses.append(f"`keyword` LIKE %(search)s")
                bind_params["search"] = search_term_like
                search_sentence = f'Searching for "{search}" in keyword (default).'

        if click_limit is not None:
            operator = ">" if click_filter == "more" else "<"

            where_clauses.append(f"clicks {operator} %(click_limit)s")
            bind_params["click_limit"] = click_limit

        if date_filter in {"before", "after", "between"} and date_first:
            if date_filter == "before":
                where_clauses.append("DATE(timestamp) < %(date_first)s")
                bind_params["date_first"] = date_first
            elif date_filter == "after":
                where_clauses.append("DATE(timestamp) > %(date_first)s")
                bind_params["date_first"] = date_first
            elif date_filter == "between" and date_second:

                where_clauses.append(
                    "DATE(timestamp) BETWEEN %(date_first)s AND %(date_second)s"
                )
                bind_params["date_first"] = date_first
                bind_params["date_second"] = date_second
            elif date_filter == "between":

                date_filter = ""

        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

        where_sql = f"WHERE {where_sql}"

        order_by_sql = f"ORDER BY `{sort_by}` {sort_order}"

        count_query = f"SELECT COUNT(*) as count FROM yourls_url {where_sql}"
        cursor.execute(count_query, bind_params)
        total_items_result = cursor.fetchone()
        total_items = total_items_result["count"] if total_items_result else 0

        total_pages = math.ceil(total_items / perpage) if total_items > 0 else 1
        if page > total_pages:
            page = total_pages
        offset = (page - 1) * perpage

        data_query = f"SELECT keyword, url, title, timestamp, clicks FROM yourls_url {where_sql} {order_by_sql} LIMIT %(limit)s OFFSET %(offset)s"

        bind_params["limit"] = perpage
        bind_params["offset"] = offset
        cursor.execute(data_query, bind_params)
        links = cursor.fetchall()

        cursor.execute(
            "SELECT COUNT(*) as count, SUM(clicks) as clicks_sum FROM yourls_url"
        )
        stats = cursor.fetchone()
        total_urls = stats["count"] if stats and stats["count"] is not None else 0
        total_clicks = (
            stats["clicks_sum"] if stats and stats["clicks_sum"] is not None else 0
        )

        context = {
            "page_title": "YOURLS Admin",
            "links": links,
            "total_urls": total_urls,
            "total_clicks": total_clicks,
            "total_items": total_items,
            "total_items_clicks": None,
            "page": page,
            "perpage": perpage,
            "total_pages": total_pages,
            "display_on_page": min(offset + 1, total_items),
            "max_on_page": min(offset + perpage, total_items),
            "sort_by": sort_by,
            "sort_order": sort_order,
            "search": search,
            "search_in": search_in,
            "search_sentence": search_sentence,
            "filter": filter_param,
            "click_filter": click_filter,
            "click_limit": click_limit_str,
            "date_filter": date_filter,
            "date_first": date_first_str,
            "date_second": date_second_str,
        }

    except Error as e:
        print(f"Error fetching data: {e}")

        context = {
            "page_title": "YOURLS Admin - Error",
            "search_sentence": f"Database query error: {e}",
            "links": [],
            "total_urls": 0,
            "total_clicks": 0,
            "total_items": 0,
            "page": 1,
            "perpage": DEFAULT_PER_PAGE,
            "total_pages": 1,
            "sort_by": DEFAULT_SORT_BY,
            "sort_order": DEFAULT_SORT_ORDER,
            "search": "",
            "search_in": "keyword",
            "filter": "",
        }
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

    return context


def sanitize_keyword(keyword):
    """Basic keyword sanitization (allows letters, numbers, dash, underscore)."""
    if not keyword:
        return None

    sanitized = re.sub(r"[^a-zA-Z0-9_-]", "", keyword)
    return sanitized if sanitized else None


def generate_next_keyword():
    """Generates the next sequential short keyword (base 36). Placeholder.
    Requires knowing the last used ID or keyword.
    """

    return "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


def format_api_response(data, format="json"):
    """Formats the API response based on the requested format."""

    if format == "xml":

        xml_parts = [f"<{key}>{value}</{key}>" for key, value in data.items()]
        return f"<result>{''.join(xml_parts)}</result>", {
            "Content-Type": "application/xml"
        }
    elif format == "simple":

        if data.get("status") == "success" and data.get("shorturl"):
            return data["shorturl"], {"Content-Type": "text/plain"}
        else:

            return f"ERROR: {data.get('message', 'Unknown error')}", {
                "Content-Type": "text/plain"
            }
    else:
        status_code = data.get(
            "statusCode", 200 if data.get("status") == "success" else 400
        )
        return jsonify(data), status_code


@app.route("/login", methods=["GET", "POST"])
def login():
    """Handles user login."""
    if current_user.is_authenticated:
        return redirect(url_for("admin_index"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.validate(username, password)

        if not user:
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

        login_user(user)

        flash("Logged in successfully.", "success")

        next_page = request.args.get("next")
        if not next_page or not next_page.startswith("/"):
            next_page = url_for("admin_index")
        return redirect(next_page)

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """Handles user logout."""
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
@login_required
def admin_index():
    """Renders the main admin page and handles link addition."""
    if request.method == "POST":

        long_url = request.form.get("url", "").strip()
        custom_keyword = request.form.get("keyword", "").strip()
        title = request.form.get("title", "").strip()

        if not long_url:
            flash("Error: URL is required.", "error")
        else:

            if not long_url.lower().startswith(("http://", "https://")):
                flash("Error: URL must start with http:// or https://.", "error")
            else:
                keyword_to_insert = sanitize_keyword(custom_keyword)
                if not keyword_to_insert:

                    keyword_to_insert = generate_next_keyword()

                if not keyword_to_insert:
                    flash("Error: Could not generate a valid keyword.", "error")
                else:

                    ip_address = request.remote_addr

                    conn = get_db_connection()
                    if not conn:
                        flash("Error: Database connection failed.", "error")
                    else:
                        cursor = None
                        try:
                            cursor = conn.cursor()
                            insert_query = """
                            INSERT INTO yourls_url (keyword, url, title, timestamp, ip, clicks)
                            VALUES (%(keyword)s, %(url)s, %(title)s, NOW(), %(ip)s, 0)
                            """
                            data = {
                                "keyword": keyword_to_insert,
                                "url": long_url,
                                "title": title if title else None,
                                "ip": ip_address,
                            }
                            cursor.execute(insert_query, data)
                            conn.commit()
                            flash(f"Short URL created: {keyword_to_insert}", "success")
                        except mysql.connector.Error as err:
                            conn.rollback()
                            if err.errno == 1062:
                                flash(
                                    f'Error: Keyword "{keyword_to_insert}" already exists.',
                                    "error",
                                )
                            else:
                                flash(f"Database Error: {err}", "error")
                                print(f"DB Error: {err}")
                        finally:
                            if cursor:
                                cursor.close()
                            if conn and conn.is_connected():
                                conn.close()

        return redirect(url_for("admin_index"))

    context = get_admin_index_data(request.args)
    return render_template("admin_index.html", **context)


@app.route("/delete/<string:keyword>", methods=["POST"])
@login_required
def delete_link(keyword): ...


@app.route("/<string:keyword>")
def redirect_link(keyword):
    """Handles the redirection and logs the click."""
    sanitized_keyword = sanitize_keyword(keyword)
    if not sanitized_keyword:
        return abort(404)

    conn = get_db_connection()
    if not conn:
        return abort(503, description="Database connection failed")

    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)

        select_query = "SELECT url FROM yourls_url WHERE keyword = %(keyword)s"
        cursor.execute(select_query, {"keyword": sanitized_keyword})
        result = cursor.fetchone()

        if result and result["url"]:
            original_url = result["url"]

            try:

                click_time = datetime.now()
                referrer = request.referrer[:200] if request.referrer else None
                user_agent = request.user_agent.string[:255]
                ip_address = request.remote_addr
                country_code = None

                log_query = """
                INSERT INTO yourls_log (click_time, shorturl, referrer, user_agent, ip_address, country_code)
                VALUES (%(time)s, %(keyword)s, %(ref)s, %(ua)s, %(ip)s, %(country)s)
                """
                log_data = {
                    "time": click_time,
                    "keyword": sanitized_keyword,
                    "ref": referrer,
                    "ua": user_agent,
                    "ip": ip_address,
                    "country": country_code,
                }
                cursor.execute(log_query, log_data)

                update_query = "UPDATE yourls_url SET clicks = clicks + 1 WHERE keyword = %(keyword)s"
                cursor.execute(update_query, {"keyword": sanitized_keyword})

                conn.commit()

            except Error as log_update_err:

                print(f"DB Error (Log/Update Clicks): {log_update_err}")
                conn.rollback()

            return redirect(original_url, code=301)
        else:
            return abort(404)

    except Error as e:
        print(f"DB Error (Redirect): {e}")

        if conn.in_transaction:
            conn.rollback()
        return abort(500, description="Database query error")
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


@app.route("/stats/<string:keyword>")
@login_required
def link_stats(keyword):
    """Displays statistics for a specific link, including recent clicks."""
    sanitized_keyword = sanitize_keyword(keyword)
    if not sanitized_keyword:
        flash(f"Invalid keyword format: {keyword}", "error")
        return redirect(url_for("admin_index"))

    conn = get_db_connection()
    if not conn:
        flash("Error: Database connection failed.", "error")
        return redirect(url_for("admin_index"))

    cursor = None
    link_data = None
    click_logs = []
    try:
        cursor = conn.cursor(dictionary=True)

        select_link_query = "SELECT keyword, url, title, timestamp, clicks FROM yourls_url WHERE keyword = %(keyword)s"
        cursor.execute(select_link_query, {"keyword": sanitized_keyword})
        link_data = cursor.fetchone()

        if not link_data:
            flash(f'Link with keyword "{sanitized_keyword}" not found.', "warning")

            return redirect(url_for("admin_index"))

        select_logs_query = """
        SELECT click_time, referrer, user_agent, ip_address, country_code 
        FROM yourls_log 
        WHERE shorturl = %(keyword)s 
        ORDER BY click_time DESC 
        LIMIT 100
        """
        cursor.execute(select_logs_query, {"keyword": sanitized_keyword})
        click_logs = cursor.fetchall()

    except Error as e:
        flash(f"Database error fetching stats: {e}", "error")
        print(f"DB Error (Stats): {e}")

        return redirect(url_for("admin_index"))
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

    return render_template("stats.html", link=link_data, logs=click_logs)


@app.route("/edit/<string:keyword>", methods=["GET", "POST"])
@login_required
def edit_link(keyword):
    """Handles displaying the edit form and updating the link."""
    original_keyword = sanitize_keyword(keyword)
    if not original_keyword:
        flash(f"Invalid original keyword format: {keyword}", "error")
        return redirect(url_for("admin_index"))

    conn = get_db_connection()
    if not conn:
        flash("Error: Database connection failed.", "error")
        return redirect(url_for("admin_index"))

    cursor = None
    try:
        if request.method == "POST":

            new_url = request.form.get("url", "").strip()
            new_keyword = request.form.get("keyword", "").strip()
            new_title = request.form.get("title", "").strip()

            if not new_url or not new_keyword:
                flash("Error: URL and Keyword cannot be empty.", "error")

                return redirect(url_for("admin_index"))

            if not new_url.lower().startswith(("http://", "https://")):
                flash("Error: URL must start with http:// or https://.", "error")
                return redirect(url_for("edit_link", keyword=original_keyword))

            sanitized_new_keyword = sanitize_keyword(new_keyword)
            if not sanitized_new_keyword:
                flash(
                    "Error: The new keyword contains invalid characters or is empty.",
                    "error",
                )
                return redirect(url_for("edit_link", keyword=original_keyword))

            cursor = conn.cursor()
            update_query = """
            UPDATE yourls_url 
            SET keyword = %(new_keyword)s, url = %(new_url)s, title = %(new_title)s
            WHERE keyword = %(original_keyword)s
            """
            data = {
                "new_keyword": sanitized_new_keyword,
                "new_url": new_url,
                "new_title": new_title if new_title else None,
                "original_keyword": original_keyword,
            }

            try:
                cursor.execute(update_query, data)

                if cursor.rowcount == 0 and original_keyword != sanitized_new_keyword:

                    flash(
                        f'Error: Could not update. The new keyword "{sanitized_new_keyword}" might already exist, or the original link was deleted.',
                        "error",
                    )
                    conn.rollback()
                    return redirect(url_for("edit_link", keyword=original_keyword))

                elif cursor.rowcount == 0:

                    flash(
                        f'Error: Could not update link "{original_keyword}". It might have been deleted.',
                        "error",
                    )
                    conn.rollback()
                    return redirect(url_for("admin_index"))
                else:
                    conn.commit()
                    flash(
                        f'Link "{sanitized_new_keyword}" updated successfully.',
                        "success",
                    )
                    return redirect(url_for("admin_index"))

            except mysql.connector.Error as err:
                conn.rollback()
                if err.errno == 1062:
                    flash(
                        f'Error: The new keyword "{sanitized_new_keyword}" already exists.',
                        "error",
                    )
                    return redirect(url_for("edit_link", keyword=original_keyword))
                else:
                    flash(f"Database Error during update: {err}", "error")
                    print(f"DB Error (Update): {err}")
                    return redirect(url_for("admin_index"))

        else:
            cursor = conn.cursor(dictionary=True)
            select_query = (
                "SELECT keyword, url, title FROM yourls_url WHERE keyword = %(keyword)s"
            )
            cursor.execute(select_query, {"keyword": original_keyword})
            link_data = cursor.fetchone()

            if not link_data:
                flash(
                    f'Link with keyword "{original_keyword}" not found for editing.',
                    "warning",
                )
                return redirect(url_for("admin_index"))

            return render_template(
                "edit_link.html", link=link_data, original_keyword=original_keyword
            )

    except Error as e:
        flash(f"Database error accessing link {original_keyword}: {e}", "error")
        print(f"DB Error (Edit GET/POST): {e}")
        return redirect(url_for("admin_index"))
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


@app.route("/api", methods=["GET", "POST"])
def api_handler():
    """Handles API requests."""

    api_key = request.values.get("apikey")
    if not API_KEY_STORE or api_key != API_KEY_STORE:

        req_format = request.values.get("format", "json").lower()
        error_response = {
            "status": "fail",
            "code": "error:auth",
            "message": "Invalid or missing API key",
            "statusCode": 403,
        }
        return format_api_response(error_response, req_format)

    action = request.values.get("action")
    req_format = request.values.get("format", "json").lower()

    if action == "shorturl":
        long_url = request.values.get("url", "").strip()
        custom_keyword = request.values.get("keyword", "").strip()
        title = request.values.get("title", "").strip()

        if not long_url:
            return format_api_response(
                {
                    "status": "fail",
                    "code": "error:url",
                    "message": "Missing URL parameter",
                    "statusCode": 400,
                },
                req_format,
            )
        if not long_url.lower().startswith(("http://", "https://")):
            return format_api_response(
                {
                    "status": "fail",
                    "code": "error:url",
                    "message": "URL format is invalid",
                    "statusCode": 400,
                },
                req_format,
            )

        keyword_to_insert = sanitize_keyword(custom_keyword)
        if not keyword_to_insert:
            keyword_to_insert = generate_next_keyword()

        if not keyword_to_insert:
            return format_api_response(
                {
                    "status": "fail",
                    "code": "error:keyword",
                    "message": "Could not generate valid keyword",
                    "statusCode": 500,
                },
                req_format,
            )

        ip_address = request.remote_addr

        conn = get_db_connection()
        if not conn:
            return format_api_response(
                {
                    "status": "fail",
                    "code": "error:db",
                    "message": "Database connection error",
                    "statusCode": 503,
                },
                req_format,
            )

        cursor = None
        try:
            cursor = conn.cursor()
            insert_query = "INSERT INTO yourls_url (keyword, url, title, timestamp, ip, clicks) VALUES (%(keyword)s, %(url)s, %(title)s, NOW(), %(ip)s, 0)"
            data = {
                "keyword": keyword_to_insert,
                "url": long_url,
                "title": title if title else None,
                "ip": ip_address,
            }
            cursor.execute(insert_query, data)
            conn.commit()

            base_url = url_for("redirect_link", keyword="", _external=True)
            shorturl_full = base_url + keyword_to_insert

            url_data = {
                "keyword": keyword_to_insert,
                "url": long_url,
                "title": title,
                "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip_address,
            }

            success_response = {
                "status": "success",
                "code": "success",
                "url": url_data,
                "message": f"{long_url} added to database",
                "title": title,
                "shorturl": shorturl_full,
                "statusCode": 200,
            }
            return format_api_response(success_response, req_format)

        except mysql.connector.Error as err:
            conn.rollback()
            if err.errno == 1062:
                return format_api_response(
                    {
                        "status": "fail",
                        "code": "error:keyword",
                        "message": f"Short URL {keyword_to_insert} already exists",
                        "statusCode": 400,
                    },
                    req_format,
                )
            else:
                print(f"DB Error (API shorturl): {err}")
                return format_api_response(
                    {
                        "status": "fail",
                        "code": "error:db",
                        "message": "Database error",
                        "statusCode": 500,
                    },
                    req_format,
                )
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    else:

        return format_api_response(
            {
                "status": "fail",
                "code": "error:action",
                "message": "Unknown action",
                "statusCode": 400,
            },
            req_format,
        )


if __name__ == "__main__":
    app.run(debug=True, port=5000)
