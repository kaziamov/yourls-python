import os
import re
import math
import random
import string
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlencode, urljoin, unquote_plus

from fastapi import FastAPI, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error
from starlette.middleware.sessions import SessionMiddleware
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
import urllib.parse


load_dotenv() 
app = FastAPI(title="YOURLS Python Adapter (FastAPI)")



app.add_middleware(
    SessionMiddleware, 
    secret_key=os.getenv('SESSION_SECRET_KEY', 'fallback-insecure-key'),
    
)


def get_db_connection():
    """Establishes a connection to the database."""
    try:
        conn = mysql.connector.connect(
            host=os.getenv('DB_HOST'),
            database=os.getenv('DB_NAME'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'), 
            port=int(os.getenv('DB_PORT')) 
        )
        if conn.is_connected():
            return conn
    except Error as e:
        print(f"Error connecting to MySQL Database: {e}")
        return None
    except ValueError:
        print(f"Error: Invalid DB_PORT value in .env. Must be an integer.")
        return None



app_root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates_path = os.path.join(app_root_path, "templates")
templates = Jinja2Templates(directory=templates_path)





try:
    app.mount("/css", StaticFiles(directory=os.path.join(app_root_path, "css")), name="css")
    app.mount("/js", StaticFiles(directory=os.path.join(app_root_path, "js")), name="js")
    app.mount("/images", StaticFiles(directory=os.path.join(app_root_path, "images")), name="images")
except RuntimeError as e:
    print(f"Static directories might not exist yet or path incorrect: {e}")
    


def simple_number_format(value):
    """Basic number format filter."""
    try:
        if isinstance(value, int):
            return f"{value:,}"
        return str(value)
    except (ValueError, TypeError):
        return str(value)

def format_datetime(value, format='%Y-%m-%d %H:%M'):
    """Formats a datetime object or timestamp string."""
    if isinstance(value, datetime):
        return value.strftime(format)
    try:
        
        
        dt_object = datetime.fromisoformat(str(value))
        return dt_object.strftime(format)
    except (ValueError, TypeError):
        return str(value) 


def generate_sort_url(request: Request, column: str, current_sort_by: str, current_sort_order: str) -> str:
    """Generates a URL for sorting the admin table.

    Args:
        request: The current request object.
        column: The column to sort by.
        current_sort_by: The currently active sort column.
        current_sort_order: The currently active sort order ('ASC' or 'DESC').

    Returns:
        A URL string for the admin index with updated sorting parameters.
    """
    params = dict(request.query_params) 
    new_sort_order = 'ASC'
    if column == current_sort_by:
        
        new_sort_order = 'DESC' if current_sort_order == 'ASC' else 'ASC'
    
    params['sort_by'] = column
    params['sort_order'] = new_sort_order
    
    
    params = {k: v for k, v in params.items() if v is not None}

    
    base_url = request.url_for('admin_index_get')
    query_string = urlencode(params)
    return f"{base_url}?{query_string}"


templates.env.filters['numberformat'] = simple_number_format
templates.env.filters['dateformat'] = format_datetime
templates.env.globals['sort_url'] = generate_sort_url 







YOURLS_URL_CONVERT_SETTING = 36 

if YOURLS_URL_CONVERT_SETTING == 62:
    SHORTURL_CHARSET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
elif YOURLS_URL_CONVERT_SETTING == 64: 
    SHORTURL_CHARSET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
else: 
    SHORTURL_CHARSET = '0123456789abcdefghijklmnopqrstuvwxyz'

BASE = len(SHORTURL_CHARSET)

VALID_SORT_COLUMNS = {'keyword', 'url', 'title', 'timestamp', 'clicks'}
VALID_SEARCH_COLUMNS = {'keyword', 'url', 'title', 'ip', 'all'}
DEFAULT_SORT_BY = 'timestamp'
DEFAULT_SORT_ORDER = 'DESC'
DEFAULT_PER_PAGE = 15
API_KEY_STORE = os.getenv('API_SECRET_KEY')


RESERVED_KEYWORDS = {
    'css', 'js', 'images', 'api', 'stats', 'edit', 'delete', 'login', 'logout',
    'admin', 'plugins', 'tools', 'info', 'yourls', 
    
}

def int2string(integer: int) -> str:
    """Converts an integer to a base string using SHORTURL_CHARSET."""
    if integer < 0:
        raise ValueError("Cannot convert negative integers.")
    if integer == 0:
        return SHORTURL_CHARSET[0]

    result = ""
    while integer > 0:
        remainder = integer % BASE
        result = SHORTURL_CHARSET[remainder] + result
        integer //= BASE
    return result

def keyword_is_reserved(keyword: str) -> bool:
    """Checks if a keyword is in the reserved list."""
    return keyword.lower() in RESERVED_KEYWORDS

def keyword_is_taken(keyword: str, conn = None) -> bool:
    """Checks if a keyword already exists in the database."""
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        if not conn:
            print("Error: DB connection failed in keyword_is_taken")
            return True 
        close_conn = True

    cursor = None
    is_taken = False
    try:
        cursor = conn.cursor()
        query = "SELECT 1 FROM yourls_url WHERE keyword = %(keyword)s LIMIT 1"
        cursor.execute(query, {'keyword': keyword})
        is_taken = cursor.fetchone() is not None
    except Error as e:
        print(f"DB Error checking keyword {keyword}: {e}")
        is_taken = True 
    finally:
        if cursor: cursor.close()
        if close_conn and conn and conn.is_connected(): conn.close()
    return is_taken

def keyword_is_free(keyword: str, conn = None) -> bool:
    """Checks if a keyword is neither reserved nor taken."""
    if keyword_is_reserved(keyword):
        return False
    return not keyword_is_taken(keyword, conn)


def sanitize_keyword(keyword: str | None, restrict_to_shorturl_charset: bool = False) -> str | None:
    """Sanitizes a keyword according to YOURLS rules.

    Args:
        keyword: The keyword string to sanitize.
        restrict_to_shorturl_charset: If True, removes all characters NOT in
                                      SHORTURL_CHARSET. If False (default), 
                                      performs basic URL sanitization (currently basic).

    Returns:
        The sanitized keyword string or None if input is None.
    """
    if not keyword: 
        return None

    if restrict_to_shorturl_charset:
        
        
        pattern = re.escape(SHORTURL_CHARSET)
        sanitized = re.sub(f'[^{pattern}]', '', keyword)
        
        sanitized = sanitized[:199]
    else:
        
        
        
        
        sanitized = re.sub(r'[\x00-\x1f\x7f]', '', keyword).strip()
        
        
        
    return sanitized if sanitized else None


MAX_KEYWORD_ATTEMPTS = 10 
INITIAL_KEYWORD_LENGTH = 4 

def generate_next_keyword(conn = None) -> str | None:
    """Generates a unique, random keyword, checking for availability."""
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        if not conn:
            print("Error: DB connection failed for keyword generation")
            return None 
        close_conn = True

    try:
        current_length = INITIAL_KEYWORD_LENGTH
        for attempt in range(MAX_KEYWORD_ATTEMPTS * current_length): 
            
            keyword = ''.join(random.choices(SHORTURL_CHARSET, k=current_length))

            if keyword_is_free(keyword, conn):
                return keyword

            
            if (attempt + 1) % MAX_KEYWORD_ATTEMPTS == 0:
                current_length += 1
                print(f"Increasing generated keyword length to {current_length}")

    except Error as e:
        print(f"Error during keyword generation: {e}")
        return None
    finally:
        if close_conn and conn and conn.is_connected(): conn.close()

    print(f"Error: Could not find a free keyword after multiple attempts.")
    return None 


def get_admin_index_data(query_params: dict) -> Dict[str, Any]:
    conn = get_db_connection()
    
    error_context = { 
        'page_title': 'YOURLS Admin - DB Error', 'total_urls': 0, 'total_clicks': 0,
        'display_on_page': 0, 'max_on_page': 0, 'total_items': 0, 'total_items_clicks': None,
        'search_sentence': 'Database connection error.', 'links': [], 'page': 1, 'perpage': DEFAULT_PER_PAGE, 
        'total_pages': 1, 'sort_by': DEFAULT_SORT_BY, 'sort_order': DEFAULT_SORT_ORDER, 'search': '', 
        'search_in': 'keyword', 'click_filter': 'more', 'click_limit': '', 'date_filter': '', 
        'date_first': '', 'date_second': ''
    }
    if not conn: return error_context

    context = {}
    cursor = None
    try:
        
        try:
            page = int(query_params.get('page', '1'))
            if page < 1: page = 1
        except ValueError: page = 1
        
        
        perpage = int(query_params.get('perpage', str(DEFAULT_PER_PAGE)))
        sort_by = query_params.get('sort_by', DEFAULT_SORT_BY).lower()
        sort_order = query_params.get('sort_order', DEFAULT_SORT_ORDER).upper()
        search = query_params.get('search', '').strip()
        search_in = query_params.get('search_in', 'keyword').lower()
        click_filter = query_params.get('click_filter', 'more').lower()
        click_limit_str = query_params.get('click_limit', '').strip()
        click_limit = int(click_limit_str) if click_limit_str.isdigit() else None
        date_filter = query_params.get('date_filter', '').lower()
        date_first_str = query_params.get('date_first', '').strip()
        date_second_str = query_params.get('date_second', '').strip()
        
        
        if perpage < 1: perpage = DEFAULT_PER_PAGE
        if sort_by not in VALID_SORT_COLUMNS: sort_by = DEFAULT_SORT_BY
        if sort_order not in {'ASC', 'DESC'}: sort_order = DEFAULT_SORT_ORDER
        if search_in not in VALID_SEARCH_COLUMNS: search_in = 'keyword'
        if click_filter not in {'more', 'less'}: click_filter = 'more'
        
        date_pattern = re.compile(r'^\d{4}-\d{2}-\d{2}$')
        date_first = date_first_str if date_pattern.match(date_first_str) else None
        date_second = date_second_str if date_pattern.match(date_second_str) else None

        
        where_clauses = []
        bind_params = {}
        search_sentence = ''
        if search:
            
            search_term_like = f"%{search}%"
            if search_in == 'all':
                where_clauses.append("CONCAT_WS('', keyword, url, title, ip) LIKE %(search)s")
                bind_params['search'] = search_term_like
                search_sentence = f"""Searching for "{search}" in all fields."""
            
            elif search_in in VALID_SEARCH_COLUMNS - {'all'}:
                 where_clauses.append(f"`{search_in}` LIKE %(search)s")
                 bind_params['search'] = search_term_like
                 search_sentence = f"Searching for \"{search}\" in {search_in}."

        if click_limit is not None:
            
            operator = '>' if click_filter == 'more' else '<'
            where_clauses.append(f"clicks {operator} %(click_limit)s")
            bind_params['click_limit'] = click_limit

        if date_filter in {'before', 'after', 'between'} and date_first:
            
            if date_filter == 'before':
                where_clauses.append("DATE(timestamp) < %(date_first)s")
                bind_params['date_first'] = date_first
            
            elif date_filter == 'after':
                 where_clauses.append("DATE(timestamp) > %(date_first)s")
                 bind_params['date_first'] = date_first
            elif date_filter == 'between' and date_second:
                 where_clauses.append("DATE(timestamp) BETWEEN %(date_first)s AND %(date_second)s")
                 bind_params['date_first'] = date_first
                 bind_params['date_second'] = date_second

        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
        where_sql = f"WHERE {where_sql}"
        order_by_sql = f"ORDER BY `{sort_by}` {sort_order}"
        
        cursor = conn.cursor(dictionary=True)

        
        count_query = f"SELECT COUNT(*) as count FROM yourls_url {where_sql}"
        cursor.execute(count_query, bind_params)
        total_items = cursor.fetchone()['count'] or 0

        total_pages = math.ceil(total_items / perpage) if total_items > 0 else 1
        if page > total_pages: page = total_pages
        offset = (page - 1) * perpage

        data_query = f"SELECT keyword, url, title, timestamp, clicks FROM yourls_url {where_sql} {order_by_sql} LIMIT %(limit)s OFFSET %(offset)s"
        bind_params['limit'] = perpage
        bind_params['offset'] = offset
        cursor.execute(data_query, bind_params)
        links = cursor.fetchall()

        cursor.execute("SELECT COUNT(*) as count, SUM(clicks) as clicks_sum FROM yourls_url")
        stats = cursor.fetchone()
        total_urls = stats['count'] or 0
        total_clicks = stats['clicks_sum'] or 0

        
        context = {
            'page_title': 'YOURLS Admin', 'links': links, 'total_urls': total_urls,
            'total_clicks': total_clicks, 'total_items': total_items, 'total_items_clicks': None, 
            'page': page, 'perpage': perpage, 'total_pages': total_pages,
            'display_on_page': min(offset + 1, total_items), 'max_on_page': min(offset + perpage, total_items),
            'sort_by': sort_by, 'sort_order': sort_order, 'search': search, 'search_in': search_in,
            'search_sentence': search_sentence, 'click_filter': click_filter, 'click_limit': click_limit_str,
            'date_filter': date_filter, 'date_first': date_first_str, 'date_second': date_second_str,
        }

    except Error as e:
        print(f"Error fetching data: {e}")
        context = error_context 
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

    return context








def add_notification(request: Request, message: str, category: str = "info"):
    """Adds a notification message to the session."""
    if "_notifications" not in request.session:
        request.session["_notifications"] = []
    request.session["_notifications"].append({"message": message, "category": category})

def get_notifications(request: Request) -> List[Dict[str, str]]:
    """Retrieves and clears notification messages from the session."""
    messages = request.session.pop("_notifications", [])
    return messages


templates.env.globals['get_notifications'] = get_notifications




ADMIN_USERNAME_STORE = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD_STORE = os.getenv('ADMIN_PASSWORD')


async def get_current_user_or_redirect(request: Request):
    user_id = request.session.get('user_id')
    if not user_id:
        
        next_url = str(request.url) 
        
        login_url_base = str(request.url_for('login_get'))
        login_url = login_url_base + f"?next={next_url}"
        
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT, 
            detail="Not authenticated",
            headers={"Location": login_url}
        )
    
    
    return user_id 



@app.get("/login", response_class=HTMLResponse, name="login_get")
async def login_get(request: Request):
    
    if request.session.get('user_id'):
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=RedirectResponse, name="login_post")
async def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    
    if username == ADMIN_USERNAME_STORE and ADMIN_PASSWORD_STORE and password == ADMIN_PASSWORD_STORE:
        
        request.session['user_id'] = 'admin' 
        add_notification(request, "Logged in successfully.", "success") 
        
        
        next_url = request.query_params.get('next', str(request.url_for('admin_index_get'))) 
        
        if not next_url.startswith('/') and not next_url.startswith(str(request.base_url)):
             next_url = str(request.url_for('admin_index_get')) 
        return RedirectResponse(url=next_url, status_code=status.HTTP_303_SEE_OTHER)
    else:
        add_notification(request, "Invalid username or password.", "error") 
        
        
        login_url_base = str(request.url_for('login_get')) 
        login_url = login_url_base + "?error=1"
        return RedirectResponse(url=login_url, status_code=status.HTTP_302_FOUND)

@app.get("/logout", response_class=RedirectResponse, name="logout")
async def logout(request: Request):
    request.session.clear()
    add_notification(request, "You have been logged out.", "success") 
    
    login_url_base = str(request.url_for('login_get')) 
    login_url = login_url_base + "?logged_out=1"
    return RedirectResponse(url=login_url, status_code=status.HTTP_303_SEE_OTHER)




@app.get("/", response_class=HTMLResponse, name="admin_index_get")
async def admin_index_get(request: Request, user_id: str = Depends(get_current_user_or_redirect)):
    context = get_admin_index_data(request.query_params)
    context["request"] = request
    context["request_args"] = request.query_params 
    context["current_user_id"] = user_id 
    
    try:
        test_url = request.url_for('admin_index_get')
        print(f"DEBUG: url_for('admin_index_get') inside route handler generated: {test_url}")
    except Exception as e:
        print(f"ERROR: url_for('admin_index_get') failed inside route handler: {e}")
    
    return templates.TemplateResponse("admin_index.html", context)

@app.route("/", methods=["GET", "POST"], name="admin_index_post")
async def add_link_endpoint(request: Request, 
                        
                        url: Optional[str] = Form(None), 
                        keyword: Optional[str] = Form(None), 
                        title: Optional[str] = Form(None),
                        
                        up: Optional[str] = None, 
                        us: Optional[str] = None, 
                        ur: Optional[str] = None, 
                        t: Optional[str] = None, 
                        s: Optional[str] = None, 
                        k: Optional[str] = None, 
                        jsonp: Optional[str] = None, 
                        
                        user_id: str = Depends(get_current_user_or_redirect)): 

    is_bookmarklet = request.method == "GET" and ur is not None
    jsonp_callback = jsonp 

    
    if is_bookmarklet:
        
        try:
            protocol = unquote_plus(up) if up else 'http:' 
            slashes = unquote_plus(us) if us else '//'
            rest_of_url = unquote_plus(ur)
            source_url = f"{protocol}{slashes}{rest_of_url}"
            source_keyword = unquote_plus(k) if k else None
            
            source_title = unquote_plus(s) if s else (unquote_plus(t) if t else "")
            source_title = source_title.strip()
        except Exception as e:
            print(f"Error decoding bookmarklet params: {e}")
            
            if jsonp:
                error_response = {"status": "fail", "message": "Error decoding parameters"}
                return PlainTextResponse(f"{jsonp}({jsonable_encoder(error_response)});", media_type="application/javascript")
            else:
                add_notification(request, "Error processing bookmarklet request.", "error")
                return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)
    elif request.method == "POST":
        
        source_url = url.strip() if url else None
        source_keyword = keyword.strip() if keyword else None
        source_title = title.strip() if title else ""
    else:
        
        raise HTTPException(status_code=405, detail="Method Not Allowed")

    
    if not source_url:
        message = "URL is required."
        if jsonp:
             error_response = {"status": "fail", "message": message}
             return PlainTextResponse(f"{jsonp}({jsonable_encoder(error_response)});", media_type="application/javascript")
        else:
            add_notification(request, message, 'error')
            return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)
            
    if not source_url.lower().startswith(('http://', 'https://')):
        message = 'Error: URL must start with http:// or https://.'
        if jsonp:
             error_response = {"status": "fail", "message": message}
             return PlainTextResponse(f"{jsonp}({jsonable_encoder(error_response)});", media_type="application/javascript")
        else:
            add_notification(request, message, 'error')
            return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)

    
    result_data = await add_new_link_core(request, source_url, source_keyword, source_title)

    
    if jsonp_callback:
        
        js_body = f"{jsonp_callback}({jsonable_encoder(result_data)});"
        return PlainTextResponse(js_body, media_type="application/javascript")
    else:
        
        notification_type = 'success' if result_data.get("status") == "success" else 'error'
        add_notification(request, result_data.get("message", "Operation finished."), notification_type)
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_303_SEE_OTHER)


@app.post("/delete/{keyword}", response_class=RedirectResponse, name="delete_link")
async def delete_link_post(request: Request, keyword: str, user_id: str = Depends(get_current_user_or_redirect)): 
    if not keyword: 
        print("Error: Invalid keyword for deletion.")
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)

    conn = get_db_connection()
    if not conn: 
        print("Error: Database connection failed.")
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)

    cursor = None
    try:
        cursor = conn.cursor()
        delete_query = "DELETE FROM yourls_url WHERE keyword = %(keyword)s"
        cursor.execute(delete_query, {'keyword': keyword})
        affected_rows = cursor.rowcount
        conn.commit()
        if affected_rows > 0: 
            add_notification(request, f'Link "{keyword}" deleted.', 'success')
        else: 
            add_notification(request, f'Link "{keyword}" not found.', 'warning')
    except Error as e:
        conn.rollback()
        add_notification(request, f'Database error during deletion: {e}', 'error')
        print(f"DB Error (Delete): {e}") 
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()
    
    return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_303_SEE_OTHER)

@app.get("/stats/{keyword}", response_class=HTMLResponse, name="link_stats")
async def link_stats_get(request: Request, keyword: str, user_id: str = Depends(get_current_user_or_redirect)): 
    
    sanitized_keyword = sanitize_keyword(keyword) 
    if not sanitized_keyword: 
        print(f"Invalid keyword format for stats lookup: {keyword}") 
        
        raise HTTPException(status_code=404, detail="Invalid keyword format")

    conn = get_db_connection()
    if not conn: 
        print("Error: Database connection failed.")
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)

    cursor = None
    link_data = None
    click_logs = []
    try:
        cursor = conn.cursor(dictionary=True)
        select_link_query = "SELECT keyword, url, title, timestamp, clicks FROM yourls_url WHERE keyword = %(keyword)s"
        cursor.execute(select_link_query, {'keyword': sanitized_keyword})
        link_data = cursor.fetchone()
        
        if not link_data:
            print(f'Link "{sanitized_keyword}" not found.')
            return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)

        select_logs_query = "SELECT click_time, referrer, user_agent, ip_address, country_code FROM yourls_log WHERE shorturl = %(keyword)s ORDER BY click_time DESC LIMIT 100"
        cursor.execute(select_logs_query, {'keyword': sanitized_keyword})
        click_logs = cursor.fetchall()

    except Error as e:
        print(f'Database error fetching stats: {e}')
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

    
    try:
        short_url_path = str(request.url_for('redirect_link', keyword=link_data['keyword']))
        base_url = str(request.base_url)
        absolute_short_url = urljoin(base_url, short_url_path.lstrip('/')) 
    except Exception as e: 
        print(f"Error generating absolute URL for stats: {e}")
        absolute_short_url = "

    
    context = {
        "request": request, 
        "link": link_data, 
        "logs": click_logs, 
        "current_user_id": user_id,
        "absolute_short_url": absolute_short_url 
    }
    return templates.TemplateResponse('stats.html', context)

@app.get("/edit/{keyword}", response_class=HTMLResponse, name="edit_link")
async def edit_link_get(request: Request, keyword: str, user_id: str = Depends(get_current_user_or_redirect)): 
    
    original_keyword_lookup = sanitize_keyword(keyword) 
    if not original_keyword_lookup: 
        print(f"Invalid keyword format for edit lookup: {keyword}")
        raise HTTPException(status_code=404, detail="Invalid keyword format")

    conn = get_db_connection()
    if not conn: 
        print("Error: Database connection failed.")
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)

    cursor = None
    link_data = None
    try:
        cursor = conn.cursor(dictionary=True)
        select_query = "SELECT keyword, url, title FROM yourls_url WHERE keyword = %(keyword)s"
        cursor.execute(select_query, {'keyword': original_keyword_lookup})
        link_data = cursor.fetchone()

        if not link_data:
            print(f'Link "{original_keyword_lookup}" not found for editing.')
            return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)
        
        
        context = {"request": request, "link": link_data, "original_keyword": keyword, "current_user_id": user_id}
        return templates.TemplateResponse('edit_link.html', context)
        
    except Error as e:
        print(f'Database error accessing link {original_keyword_lookup}: {e}')
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

@app.post("/edit/{keyword}", response_class=RedirectResponse, name="edit_link_post")
async def edit_link_post(request: Request, 
                         keyword: str, 
                         url: str = Form(...), 
                         new_keyword: str = Form(..., alias="keyword"), 
                         title: Optional[str] = Form(None),
                         user_id: str = Depends(get_current_user_or_redirect)): 
    
    original_keyword_lookup = sanitize_keyword(keyword) 
    
    new_url_strip = url.strip()
    new_keyword_strip = new_keyword.strip()
    new_title_strip = title.strip() if title else ""

    if not new_url_strip or not new_keyword_strip:
        print('Error: URL and Keyword cannot be empty.')
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)
    if not new_url_strip.lower().startswith(('http://', 'https://')):
        print('Error: URL must start with http:// or https://.')
        
        edit_url = request.url_for('edit_link', keyword=original_keyword_lookup or keyword)
        return RedirectResponse(url=edit_url, status_code=status.HTTP_302_FOUND)

    
    sanitized_new_keyword = sanitize_keyword(new_keyword_strip, restrict_to_shorturl_charset=True)
    if not sanitized_new_keyword:
        print(f'Error: The new keyword "{new_keyword_strip}" contains invalid characters or is empty after sanitization.')
        
        edit_url = request.url_for('edit_link', keyword=original_keyword_lookup or keyword) 
        add_notification(request, 'Error: The new keyword contains invalid characters or is empty after sanitization.', 'error')
        return RedirectResponse(url=edit_url, status_code=status.HTTP_302_FOUND)

    conn = get_db_connection()
    if not conn: 
        print("Error: Database connection failed.")
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)

    cursor = None
    redirect_to_edit = False
    try:
        cursor = conn.cursor()
        update_query = "UPDATE yourls_url SET keyword = %(new_keyword)s, url = %(new_url)s, title = %(new_title)s WHERE keyword = %(original_keyword)s"
        data = {
            'new_keyword': sanitized_new_keyword, 
            'new_url': new_url_strip, 
            'new_title': new_title_strip if new_title_strip else None, 
            'original_keyword': original_keyword_lookup 
        }
        cursor.execute(update_query, data)
        
        if cursor.rowcount == 0:
             conn.rollback()
             add_notification(request, f'Error: Could not update link "{original_keyword_lookup}". It might have been deleted or new keyword exists.', 'error')
             redirect_to_edit = True 
        else:
            conn.commit()
            add_notification(request, f'Link "{sanitized_new_keyword}" updated.', 'success')

    except Error as err:
         conn.rollback()
         if err.errno == 1062:
             add_notification(request, f'Error: The new keyword "{sanitized_new_keyword}" already exists.', 'error')
         else:
             add_notification(request, f'Database Error during update: {err}', 'error')
             print(f"DB Error (Update): {err}") 
         redirect_to_edit = True 
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

    if redirect_to_edit:
        
        edit_url = request.url_for('edit_link', keyword=original_keyword_lookup or keyword)
        return RedirectResponse(url=edit_url, status_code=status.HTTP_302_FOUND)
    else:
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_303_SEE_OTHER)



def format_api_response(data: Dict[str, Any], req_format: str = 'json') -> Tuple[Any, int, Dict[str, str]]:
    """Formats the API response data into JSON, XML (basic), or Simple Text."""
    simple_output = data.pop('simple', None) 
    status_code = data.pop('statusCode', 200)
    headers = {}
    content = data 

    if req_format == 'xml':
        
        xml_parts = [f"<{key}>{value}</{key}>" for key, value in data.items() if value is not None]
        content = f"<?xml version=\"1.0\" encoding=\"UTF-8\"?><result>{''.join(xml_parts)}</result>"
        headers['Content-Type'] = 'application/xml'
    elif req_format == 'simple':
        content = simple_output if simple_output is not None else data.get('message', 'Error')
        headers['Content-Type'] = 'text/plain'
        if data.get('status') != 'success' and status_code == 200:
            status_code = 400 
    else: 
        headers['Content-Type'] = 'application/json'
        content = data 
        
    return content, status_code, headers

@app.api_route("/api", methods=["GET", "POST"], name="api_handler", response_model=None) 
async def api_handler_route(request: Request):
    params = {}
    if request.method == "POST":
        try:
            
            if request.headers.get("content-type") == "application/json":
                params = await request.json()
            else:
                 
                params = {**request.query_params, **await request.form()}
        except Exception: 
             params = {**request.query_params, **await request.form()} if await request.body() else {**request.query_params}
    else: 
        params = {**request.query_params}

    
    api_key_param = params.get('apikey') 
    
    
    
    
    authenticated = False
    if API_KEY_STORE:
        if api_key_param and api_key_param == API_KEY_STORE:
            authenticated = True
        
        
        
        
        
        
    
    
    
        
    req_format = params.get('format', 'json').lower()
    jsonp_callback = params.get('callback') or params.get('jsonp')
    if jsonp_callback:
        req_format = 'jsonp' 

    if not authenticated:
        error_response = {"status": "fail", "code": "error:auth", "message": "Invalid or missing authentication credentials", "statusCode": 403}
        content, status_code, headers = format_api_response(error_response, req_format if req_format != 'jsonp' else 'json')
        if jsonp_callback:
             js_body = f"{jsonp_callback}({jsonable_encoder(content)});"
             return PlainTextResponse(js_body, status_code=status_code, media_type="application/javascript")
        elif req_format == 'xml' or req_format == 'simple':
             return PlainTextResponse(content, status_code=status_code, headers=headers)
        else:
             return JSONResponse(content=content, status_code=status_code, headers=headers)

    
    action = params.get('action')
    response_data = {}

    if action == 'shorturl':
        source_url = params.get('url', '').strip()
        source_keyword = params.get('keyword', '').strip() or None
        source_title = params.get('title', '').strip() or None
        
        
        if not source_url or not source_url.lower().startswith(('http://', 'https://')):
             response_data = {"status": "fail", "message": "Missing or invalid URL parameter.", "statusCode": 400}
        else:
            response_data = await add_new_link_core(request, source_url, source_keyword, source_title)
            
            if response_data.get('status') == 'success':
                 response_data['simple'] = response_data.get('shorturl')
            else:
                 response_data['simple'] = response_data.get('message')

    elif action == 'expand':
        shorturl_param = params.get('shorturl', '').strip()
        keyword = sanitize_keyword(shorturl_param.split('/')[-1]) 
        
        if not keyword:
            response_data = {"status": "fail", "message": "Missing or invalid shorturl parameter.", "statusCode": 400}
        else:
            conn = get_db_connection()
            if not conn:
                response_data = {"status": "fail", "message": "Database connection error.", "statusCode": 503}
            else:
                cursor = None
                try:
                    cursor = conn.cursor(dictionary=True)
                    query = "SELECT url, title FROM yourls_url WHERE keyword = %(keyword)s"
                    cursor.execute(query, {'keyword': keyword})
                    result = cursor.fetchone()
                    if result and result['url']:
                         response_data = {
                            'keyword': keyword,
                            'shorturl': str(request.base_url).rstrip('/') + '/' + keyword,
                            'longurl': result['url'],
                            'title': result['title'],
                            'simple': result['url'],
                            'message': 'success',
                            'statusCode': 200,
                        }
                    else:
                         response_data = {
                            'keyword': keyword,
                            'simple': 'not found',
                            'message': 'Error: short URL not found',
                            'statusCode': 404,
                        }
                except Error as e:
                    print(f"DB Error (API Expand): {e}")
                    response_data = {"status": "fail", "message": "Database query error.", "statusCode": 500}
                finally:
                    if cursor: cursor.close()
                    if conn and conn.is_connected(): conn.close()
                    
    elif action == 'version':
        
        app_version = "1.0-fastapi" 
        response_data = {'version': app_version, 'simple': app_version, 'statusCode': 200}
        
        
        

    elif action == 'db-stats':
        stats = get_db_stats_core()
        response_data = {
            'db_stats': stats, 
            'message': 'success',
            'simple': 'DB Stats: Links: {:,}, Clicks: {:,}'.format(stats['total_links'], stats['total_clicks']), 
            'statusCode': 200
        }

    elif action == 'url-stats':
        shorturl_param = params.get('shorturl', '').strip()
        keyword = sanitize_keyword(shorturl_param.split('/')[-1]) 

        if not keyword:
            response_data = {"status": "fail", "message": "Missing or invalid shorturl parameter.", "statusCode": 400}
        else:
            link_stats = get_url_stats_core(keyword)
            if link_stats:
                
                link_short_url = str(request.base_url).rstrip('/') + '/' + link_stats['keyword']
                response_data = {
                    'statusCode': 200,
                    'message': 'success',
                    'link': { 
                        'shorturl': link_short_url,
                        'url': link_stats['url'],
                        'title': link_stats['title'],
                        'timestamp': link_stats['timestamp'],
                        'ip': link_stats['ip'],
                        'clicks': link_stats['clicks']
                    }
                }
            else:
                 response_data = {
                    'statusCode': 404,
                    'message': 'Error: short URL not found'
                }
            
            response_data['simple'] = f"Clicks: {link_stats['clicks']}" if link_stats else "not found"

    elif action == 'stats':
        filter_type = params.get('filter', 'top')
        limit = params.get('limit', 10)
        start = params.get('start', 0)
        
        stats_result = get_filtered_links_core(filter_type, limit, start)
        
        response_data = {
            'statusCode': 200,
            'message': 'success',
            'links': stats_result.get('links', {}), 
            'stats': stats_result.get('stats', {}), 
            'simple': 'Stats requires JSON or XML format' 
        }

    else:
        response_data = {"status": "fail", "code": "error:action", "message": "Unknown action", "statusCode": 400}

    
    final_content, final_status_code, final_headers = format_api_response(response_data.copy(), req_format if req_format != 'jsonp' else 'json')

    if jsonp_callback:
        js_body = f"{jsonp_callback}({jsonable_encoder(final_content)});"
        return PlainTextResponse(js_body, status_code=final_status_code, media_type="application/javascript", headers=final_headers)
    elif req_format == 'xml' or req_format == 'simple':
        return PlainTextResponse(final_content, status_code=final_status_code, headers=final_headers)
    else: 
        return JSONResponse(content=final_content, status_code=final_status_code, headers=final_headers)


@app.get("/{keyword}", response_class=RedirectResponse, name="redirect_link")
async def redirect_link_get(request: Request, keyword: str):
    
    sanitized_keyword = sanitize_keyword(keyword) 
    if not sanitized_keyword: 
        raise HTTPException(status_code=404, detail="Keyword not found (invalid format)")

    conn = get_db_connection()
    if not conn: 
        raise HTTPException(status_code=503, detail="Database connection failed")

    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        select_query = "SELECT url FROM yourls_url WHERE keyword = %(keyword)s"
        cursor.execute(select_query, {'keyword': sanitized_keyword})
        result = cursor.fetchone()
        
        if result and result['url']:
            original_url = result['url']
            
            
            try:
                click_time = datetime.now()
                referrer = request.headers.get('referer', None)
                user_agent = request.headers.get('user-agent', 'Unknown')[:255] 
                ip_address = request.client.host
                country_code = None 

                
                log_query = """
                    INSERT INTO yourls_log 
                    (click_time, shorturl, referrer, user_agent, ip_address, country_code) 
                    VALUES (%(click_time)s, %(shorturl)s, %(referrer)s, %(user_agent)s, %(ip_address)s, %(country_code)s)
                    """
                log_data = {
                    'click_time': click_time,
                    'shorturl': sanitized_keyword,
                    'referrer': referrer,
                    'user_agent': user_agent,
                    'ip_address': ip_address,
                    'country_code': country_code
                }
                cursor.execute(log_query, log_data)

                
                update_query = "UPDATE yourls_url SET clicks = clicks + 1 WHERE keyword = %(keyword)s"
                cursor.execute(update_query, {'keyword': sanitized_keyword})
                conn.commit() 
            except Error as log_update_err:
                
                print(f"DB Error (Log/Update Clicks): {log_update_err}")
                
                if conn.in_transaction: conn.rollback()

            
            return RedirectResponse(url=original_url, status_code=status.HTTP_301_MOVED_PERMANENTLY)
        else:
            
            raise HTTPException(status_code=404, detail="Keyword not found")

    except Error as e:
        print(f"DB Error (Redirect): {e}")
        if conn.in_transaction: conn.rollback()
        raise HTTPException(status_code=500, detail="Database query error")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()



def make_bookmarklet(js_code: str) -> str:
    """Formats JavaScript code into a javascript: URL."""
    
    
    formatted_js = f"(function(){{{js_code.strip()}}})();"
    
    
    encoded_js = urllib.parse.quote_plus(formatted_js, safe=":/?&=()'") 
    return f"javascript:{encoded_js}"


@app.get("/tools", response_class=HTMLResponse, name="tools_get")
async def tools_get(request: Request, user_id: str = Depends(get_current_user_or_redirect)):
    base_bookmarklet_url_raw = str(request.url_for('admin_index_post')) 
    base_bookmarklet_url = urllib.parse.urljoin(str(request.base_url), base_bookmarklet_url_raw)
    
    safe_base_url = base_bookmarklet_url.replace("'", "\\'") 

    
    standard_simple_js = '''
        var d=document,w=window,enc=encodeURIComponent,e=w.getSelection,k=d.getSelection,x=d.selection,
            s=(e?e():(k?k():(x?x.createRange().text:0))),s2=((s.toString()=='')?s:enc(s)),
            f='{base_url}',l=d.location.href,
            ups=l.match(/^[a-zA-Z0-9\+\.-]+:(\/\/)?/)[0],ur=l.split(new RegExp(ups))[1],ups=ups.split(/:/),
            p='?up='+enc(ups[0]+':')+'&us='+enc(ups[1])+'&ur='+enc(ur)+'&t='+enc(d.title)+'&s='+s2,u=f+p;
        try{{throw('ozh');}}catch(z){{a=function(){{if(!w.open(u))l.href=u;}};if(/Firefox/.test(navigator.userAgent))setTimeout(a,0);else a();}}
        void(0);
    '''.format(base_url=safe_base_url)

    popup_simple_js = '''
        var d=document,sc=d.createElement('script'),l=d.location.href,enc=encodeURIComponent,
            ups=l.match(/^[a-zA-Z0-9\+\.-]+:(\/\/)?/)[0],ur=l.split(new RegExp(ups))[1],ups=ups.split(/:/),
            p='?up='+enc(ups[0]+':')+'&us='+enc(ups[1])+'&ur='+enc(ur)+'&t='+enc(d.title);
        window.yourls_callback=function(r){{if(r.shorturl){{prompt(r.message,r.shorturl);}}else{{alert('An error occurred: '+r.message);}};}};
        sc.src='{base_url}'+p+'&jsonp=yourls_callback';
        void(d.body.appendChild(sc));
    '''.format(base_url=safe_base_url)

    custom_standard_js = '''
        var d=document,enc=encodeURIComponent,w=window,e=w.getSelection,k_sel=d.getSelection,x=d.selection,
            s=(e?e():(k_sel?k_sel():(x?x.createRange().text:0))),s2=((s.toString()=='')?s:enc(s)),
            f='{base_url}',l=d.location.href,
            ups=l.match(/^[a-zA-Z0-9\+\.-]+:(\/\/)?/)[0],ur=l.split(new RegExp(ups))[1],ups=ups.split(/:/),
            k=prompt("Custom keyword for "+l),k2=(k?'&k='+enc(k):""),
            p='?up='+enc(ups[0]+':')+'&us='+enc(ups[1])+'&ur='+enc(ur)+'&t='+enc(d.title)+'&s='+s2+k2,u=f+p;
        if(k!=null){{try{{throw('ozh');}}catch(z){{a=function(){{if(!w.open(u))l.href=u;}};if(/Firefox/.test(navigator.userAgent))setTimeout(a,0);else a();}}void(0)}}
    '''.format(base_url=safe_base_url)

    custom_popup_js = '''
        var d=document,l=d.location.href,k=prompt('Custom keyword for '+l),enc=encodeURIComponent,
            ups=l.match(/^[a-zA-Z0-9\+\.-]+:(\/\/)?/)[0],ur=l.split(new RegExp(ups))[1],ups=ups.split(/:/),
            p='?up='+enc(ups[0]+':')+'&us='+enc(ups[1])+'&ur='+enc(ur)+'&t='+enc(d.title),sc=d.createElement('script');
        if(k!=null){{window.yourls_callback=function(r){{if(r.shorturl){{prompt(r.message,r.shorturl);}}else{{alert('An error occurred: '+r.message);}};}};sc.src='{base_url}'+p+'&k='+enc(k)+'&jsonp=yourls_callback';void(d.body.appendChild(sc));}}
    '''.format(base_url=safe_base_url)

    facebook_js = '''
        var d=document,w=window,enc=encodeURIComponent,l=d.location.href,
            f='{base_url}',p='?url='+enc(l)+'&source=fb_bm';
        a=function(){{if(!w.open(f+p))l.href=f+p;}};if(/Firefox/.test(navigator.userAgent))setTimeout(a,0);else a();void(0);
    '''.format(base_url=safe_base_url)

    twitter_js = '''
        var d=document,w=window,enc=encodeURIComponent,l=d.location.href,
            s=w.getSelection?w.getSelection():(d.getSelection?d.getSelection():(d.selection?d.selection.createRange().text:0)),
            s2=((s.toString()=='')?s:enc(' "' + s + '"')),
            f='{base_url}',p='?url='+enc(l)+'&title='+enc(d.title)+s2+'&source=tw_bm';
        a=function(){{if(!w.open(f+p))l.href=f+p;}};if(/Firefox/.test(navigator.userAgent))setTimeout(a,0);else a();void(0);
    '''.format(base_url=safe_base_url)
    
    bookmarklets = {
        'standard_simple': make_bookmarklet(standard_simple_js),
        'popup_simple': make_bookmarklet(popup_simple_js),
        'custom_standard': make_bookmarklet(custom_standard_js),
        'custom_popup': make_bookmarklet(custom_popup_js),
        'facebook': make_bookmarklet(facebook_js),
        'twitter': make_bookmarklet(twitter_js),
    }
    
    context = {
        "request": request, 
        "page_title": "YOURLS Tools", 
        "bookmarklets": bookmarklets,
        "current_user_id": user_id
    }
    return templates.TemplateResponse("tools.html", context)



async def add_new_link_core(request: Request, source_url: str, source_keyword: Optional[str], source_title: Optional[str]) -> Dict[str, Any]:
    """Core logic for adding a new link. Returns a dictionary with result."""
    conn = None
    cursor = None
    final_keyword = None
    response_data = {}
    status_code = 200

    try:
        
        
        

        conn = get_db_connection()
        if not conn:
            raise Exception("Database connection error.")

        if source_keyword:
            sanitized_custom_keyword = sanitize_keyword(source_keyword, restrict_to_shorturl_charset=True)
            if not sanitized_custom_keyword:
                 raise ValueError(f'Custom keyword "{source_keyword}" contains invalid characters or is empty after sanitization.')
            if not keyword_is_free(sanitized_custom_keyword, conn):
                 raise ValueError(f'Custom keyword "{sanitized_custom_keyword}" is already taken or reserved.')
            final_keyword = sanitized_custom_keyword
        else:
            final_keyword = generate_next_keyword(conn)
            if not final_keyword:
                 raise Exception('Could not generate a unique keyword.')

        final_title = source_title 
        
        cursor = conn.cursor()
        insert_query = """
            INSERT INTO yourls_url (keyword, url, title, timestamp, ip, clicks) 
            VALUES (%(keyword)s, %(url)s, %(title)s, NOW(), %(ip)s, 0)
            """
        link_data = {
            'keyword': final_keyword,
            'url': source_url,
            'title': final_title if final_title else None,
            'ip': request.client.host if request else 'api' 
        }
        cursor.execute(insert_query, link_data)
        conn.commit()
        
        short_url_base = str(request.base_url) if request else 'http://localhost/' 
        short_url = short_url_base.rstrip('/') + '/' + final_keyword
        response_data = {
            "status": "success", "message": f'Link {final_keyword} added to database',
            "title": final_title, "shorturl": short_url, "keyword": final_keyword,
            "url": { "keyword": final_keyword, "url": source_url, "title": final_title, 
                     "date": datetime.now().isoformat(), "ip": link_data['ip'], "clicks": 0 }
        }
        status_code = 200

    except (ValueError, Exception) as e: 
        if conn and conn.in_transaction: conn.rollback()
        error_message = str(e)
        print(f"Error in add_new_link_core: {error_message}")
        response_data = {"status": "fail", "message": error_message}
        status_code = 400 
        final_keyword = None 
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()
        
    
    response_data['statusCode'] = status_code 
    return response_data



def get_db_stats_core() -> Dict[str, Any]:
    """Fetches total link count and total clicks from the database."""
    conn = get_db_connection()
    stats = {'total_links': 0, 'total_clicks': 0}
    if not conn:
        print("Error: DB connection failed for get_db_stats_core")
        return stats 

    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) as count, SUM(clicks) as clicks_sum FROM yourls_url")
        result = cursor.fetchone()
        if result:
            stats['total_links'] = result['count'] or 0
            
            stats['total_clicks'] = int(result['clicks_sum'] or 0) 
    except Error as e:
        print(f"DB Error getting DB stats: {e}")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()
    return stats

def get_url_stats_core(keyword: str) -> Dict[str, Any]:
    """Fetches statistics for a specific keyword."""
    conn = get_db_connection()
    link_stats = None
    if not conn:
        print("Error: DB connection failed for get_url_stats_core")
        return None

    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT keyword, url, title, timestamp, ip, clicks FROM yourls_url WHERE keyword = %(keyword)s"
        cursor.execute(query, {'keyword': keyword})
        link_stats = cursor.fetchone()
        
        if link_stats and isinstance(link_stats.get('timestamp'), datetime):
             link_stats['timestamp'] = link_stats['timestamp'].isoformat()
            
    except Error as e:
        print(f"DB Error getting URL stats for {keyword}: {e}")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()
    return link_stats

def get_filtered_links_core(filter_type: str = 'top', limit: int = 10, start: int = 0) -> Dict[str, Any]:
    """Fetches a list of links based on filter type (top, bottom, last, rand) and pagination."""
    conn = get_db_connection()
    result = {"links": [], "stats": {"filter": filter_type, "limit": limit, "start": start, "count": 0}}
    if not conn:
        print("Error: DB connection failed for get_filtered_links_core")
        return result

    valid_filters = {'top': 'clicks DESC', 'bottom': 'clicks ASC', 'last': 'timestamp DESC', 'rand': 'RAND()'}
    order_by = valid_filters.get(filter_type.lower(), valid_filters['top']) 

    
    try:
        limit = int(limit)
        start = int(start)
        if limit <= 0: limit = 10
        if start < 0: start = 0
    except (ValueError, TypeError):
        limit = 10
        start = 0

    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        query = f"""
            SELECT keyword, url, title, timestamp, ip, clicks 
            FROM yourls_url 
            ORDER BY {order_by} 
            LIMIT %(limit)s OFFSET %(offset)s
        """
        cursor.execute(query, {'limit': limit, 'offset': start})
        links = cursor.fetchall()
        
        
        for link in links:
            if isinstance(link.get('timestamp'), datetime):
                link['timestamp'] = link['timestamp'].isoformat()

        result["links"] = {
            f"link_{i}": link for i, link in enumerate(links) 
        }
        result["stats"]["count"] = len(links)

    except Error as e:
        print(f"DB Error getting filtered links ({filter_type}): {e}")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()
    return result


