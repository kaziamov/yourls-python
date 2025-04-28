import os
import re
import math
import random
import string
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlencode, urljoin

from fastapi import FastAPI, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error
from starlette.middleware.sessions import SessionMiddleware


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





VALID_SORT_COLUMNS = {'keyword', 'url', 'title', 'timestamp', 'clicks'}
VALID_SEARCH_COLUMNS = {'keyword', 'url', 'title', 'ip', 'all'}
DEFAULT_SORT_BY = 'timestamp'
DEFAULT_SORT_ORDER = 'DESC'
DEFAULT_PER_PAGE = 15
API_KEY_STORE = os.getenv('API_SECRET_KEY') 


def sanitize_keyword(keyword):
    if not keyword: return None
    sanitized = re.sub(r'[^a-zA-Z0-9_-]', '', keyword)
    return sanitized if sanitized else None

def generate_next_keyword():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))



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

@app.post("/", response_class=RedirectResponse, name="admin_index_post")
async def admin_index_post(request: Request, 
                         url: str = Form(...), 
                         keyword: Optional[str] = Form(None), 
                         title: Optional[str] = Form(None),
                         user_id: str = Depends(get_current_user_or_redirect)): 
    long_url = url.strip()
    custom_keyword = keyword.strip() if keyword else ""
    link_title = title.strip() if title else "" 
    
    if not long_url:
        
        print("Error: URL is required.")
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)
    if not long_url.lower().startswith(('http://', 'https://')):
        print("Error: URL must start with http:// or https://.")
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)

    keyword_to_insert = sanitize_keyword(custom_keyword)
    if not keyword_to_insert:
        keyword_to_insert = generate_next_keyword() 

    if not keyword_to_insert:
         print("Error: Could not generate a valid keyword.")
         return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)

    ip_address = request.client.host
    conn = get_db_connection()
    if not conn:
         print("Error: Database connection failed.")
         return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)
    
    cursor = None
    try:
        cursor = conn.cursor()
        insert_query = "INSERT INTO yourls_url (keyword, url, title, timestamp, ip, clicks) VALUES (%(keyword)s, %(url)s, %(title)s, NOW(), %(ip)s, 0)"
        data = {'keyword': keyword_to_insert, 'url': long_url, 'title': link_title if link_title else None, 'ip': ip_address}
        cursor.execute(insert_query, data)
        conn.commit()
        add_notification(request, f'Short URL created: {keyword_to_insert}', 'success')
    except Error as err:
        conn.rollback()
        if err.errno == 1062:
            add_notification(request, f'Error: Keyword "{keyword_to_insert}" already exists.', 'error')
        else:
            add_notification(request, f'Database Error: {err}', 'error')
            print(f"DB Error: {err}") 
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

    
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
        print(f"Invalid keyword format: {keyword}")
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)

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

    # Construct absolute short URL in Python
    try:
        short_url_path = str(request.url_for('redirect_link', keyword=link_data['keyword']))
        base_url = str(request.base_url)
        absolute_short_url = urljoin(base_url, short_url_path.lstrip('/')) # Use urljoin for robust joining
    except Exception as e: # Catch potential errors during URL generation
        print(f"Error generating absolute URL for stats: {e}")
        absolute_short_url = "#error" # Fallback URL

    # Prepare context for the template
    context = {
        "request": request, 
        "link": link_data, 
        "logs": click_logs, 
        "current_user_id": user_id,
        "absolute_short_url": absolute_short_url # Pass the generated URL
    }
    return templates.TemplateResponse('stats.html', context)

@app.get("/edit/{keyword}", response_class=HTMLResponse, name="edit_link")
async def edit_link_get(request: Request, keyword: str, user_id: str = Depends(get_current_user_or_redirect)): 
    original_keyword = sanitize_keyword(keyword)
    if not original_keyword: 
        print(f"Invalid keyword format: {keyword}")
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)

    conn = get_db_connection()
    if not conn: 
        print("Error: Database connection failed.")
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)

    cursor = None
    link_data = None
    try:
        cursor = conn.cursor(dictionary=True)
        select_query = "SELECT keyword, url, title FROM yourls_url WHERE keyword = %(keyword)s"
        cursor.execute(select_query, {'keyword': original_keyword})
        link_data = cursor.fetchone()

        if not link_data:
            print(f'Link "{original_keyword}" not found for editing.')
            return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)
        
        context = {"request": request, "link": link_data, "original_keyword": original_keyword, "current_user_id": user_id}
        return templates.TemplateResponse('edit_link.html', context)
        
    except Error as e:
        print(f'Database error accessing link {original_keyword}: {e}')
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
    original_keyword = sanitize_keyword(keyword)
    new_url_strip = url.strip()
    new_keyword_strip = new_keyword.strip()
    new_title_strip = title.strip() if title else ""

    if not new_url_strip or not new_keyword_strip:
        print('Error: URL and Keyword cannot be empty.')
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_302_FOUND)
    if not new_url_strip.lower().startswith(('http://', 'https://')):
        print('Error: URL must start with http:// or https://.')
        
        edit_url = request.url_for('edit_link', keyword=original_keyword)
        return RedirectResponse(url=edit_url, status_code=status.HTTP_302_FOUND)

    sanitized_new_keyword = sanitize_keyword(new_keyword_strip)
    if not sanitized_new_keyword:
        print('Error: The new keyword contains invalid characters or is empty.')
        edit_url = request.url_for('edit_link', keyword=original_keyword)
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
            'new_keyword': sanitized_new_keyword, 'new_url': new_url_strip, 
            'new_title': new_title_strip if new_title_strip else None, 'original_keyword': original_keyword
        }
        cursor.execute(update_query, data)
        
        if cursor.rowcount == 0:
             conn.rollback()
             add_notification(request, f'Error: Could not update link "{original_keyword}". It might have been deleted or new keyword exists.', 'error')
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
        edit_url = request.url_for('edit_link', keyword=original_keyword)
        return RedirectResponse(url=edit_url, status_code=status.HTTP_302_FOUND)
    else:
        return RedirectResponse(url=request.url_for('admin_index_get'), status_code=status.HTTP_303_SEE_OTHER)



def format_api_response(data, format='json'):
    if format == 'xml':
        xml_parts = [f"<{key}>{value}</{key}>" for key, value in data.items()]
        return f"<result>{''.join(xml_parts)}</result>", 200, {'Content-Type': 'application/xml'} 
    elif format == 'simple':
        if data.get('status') == 'success' and data.get('shorturl'):
             return data['shorturl'], 200, {'Content-Type': 'text/plain'}
        else:
             return f"ERROR: {data.get('message', 'Unknown error')}", data.get('statusCode', 400), {'Content-Type': 'text/plain'}
    else: 
        status_code = data.get('statusCode', 200 if data.get('status') == 'success' else 400)
        return data, status_code 

@app.api_route("/api", methods=["GET", "POST"], name="api_handler") 
async def api_handler_route(request: Request):
    
    params = {**request.query_params, **await request.form()} if request.method == "POST" else request.query_params
    
    api_key = params.get('apikey')
    req_format = params.get('format', 'json').lower()

    if not API_KEY_STORE or api_key != API_KEY_STORE:
        error_response = {"status": "fail", "code": "error:auth", "message": "Invalid or missing API key", "statusCode": 403}
        content, status_code, headers = format_api_response(error_response, req_format)
        
        if req_format == 'xml' or req_format == 'simple':
             return HTMLResponse(content=content, status_code=status_code, headers=headers)
        else:
             return await app.exception_handler(HTTPException(status_code=status_code, detail=content)) 


    action = params.get('action')

    if action == 'shorturl':
        long_url = params.get('url', '').strip()
        
        
        
        
        
        
        
        
        
        success_response = {"status": "success", "message": "shorturl placeholder", "shorturl": "http://.../placeholder", "statusCode": 200}
        content, status_code, headers = format_api_response(success_response, req_format)
        if req_format == 'xml' or req_format == 'simple':
            return HTMLResponse(content=content, status_code=status_code, headers=headers)
        else:
            return success_response 


    
    
    else:
        
        error_response = {"status": "fail", "code": "error:action", "message": "Unknown action", "statusCode": 400}
        content, status_code, headers = format_api_response(error_response, req_format)
        if req_format == 'xml' or req_format == 'simple':
             return HTMLResponse(content=content, status_code=status_code, headers=headers)
        else:
            raise HTTPException(status_code=status_code, detail=content) 


@app.get("/{keyword}", response_class=RedirectResponse, name="redirect_link")
async def redirect_link_get(request: Request, keyword: str):
    sanitized_keyword = sanitize_keyword(keyword)
    if not sanitized_keyword: 
        raise HTTPException(status_code=404, detail="Keyword not found")

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

                log_query = "INSERT INTO yourls_log (...) VALUES (...)"
                log_data = { ... }
                cursor.execute(log_query, log_data)

                update_query = "UPDATE yourls_url SET clicks = clicks + 1 WHERE keyword = %(keyword)s"
                cursor.execute(update_query, {'keyword': sanitized_keyword})
                conn.commit()
            except Error as log_update_err:
                print(f"DB Error (Log/Update Clicks): {log_update_err}")
                conn.rollback()

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


