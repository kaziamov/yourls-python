import os
from flask import Flask, render_template, request, url_for, flash, redirect, abort
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error
from datetime import datetime
import math
import re
import random
import string

load_dotenv()  # Load variables from .env file

app = Flask(__name__)

# Configure Secret Key for flash messages
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-should-be-changed')

# Configure Jinja2 to load templates from the 'templates' directory
app.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')

# --- Constants & Config ---
# Valid columns for sorting and searching
VALID_SORT_COLUMNS = {'keyword', 'url', 'title', 'timestamp', 'clicks'}
VALID_SEARCH_COLUMNS = {'keyword', 'url', 'title', 'ip'} # IP is searchable in YOURLS
DEFAULT_SORT_BY = 'timestamp'
DEFAULT_SORT_ORDER = 'DESC'
DEFAULT_PER_PAGE = 15

# --- Database Connection ---
def get_db_connection():
    """Establishes a connection to the database."""
    try:
        conn = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            database=os.getenv('DB_NAME'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            port=int(os.getenv('DB_PORT', 3306)) # Ensure port is int
        )
        if conn.is_connected():
            # print('Connected to MySQL database') # Optional: for debugging
            return conn
    except Error as e:
        print(f"Error connecting to MySQL Database: {e}")
        # TODO: Handle connection error more gracefully (e.g., show error page)
        return None
    except ValueError:
        print(f"Error: Invalid DB_PORT value in .env. Must be an integer.")
        return None

# --- Jinja2 Filters & Globals ---
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
        # Assuming value might be a string representation from DB
        dt_object = datetime.fromisoformat(str(value))
        return dt_object.strftime(format)
    except (ValueError, TypeError):
        return str(value) # Return as string if formatting fails

# Helper function for sorting URLs
def generate_sort_url(column_name, current_sort_by, current_sort_order, current_args):
    """Generates URL for sorting table columns, preserving other query params."""
    args = current_args.copy()
    args['sort_by'] = column_name
    # Determine next sort order
    if current_sort_by == column_name and current_sort_order == 'ASC':
        args['sort_order'] = 'DESC'
    else:
        args['sort_order'] = 'ASC' # Default to ASC on new column or if current is DESC
    # Reset page to 1 when changing sort column?
    # args['page'] = 1 # Optional: Reset page when sort changes
    return url_for('admin_index', **args)

# Helper function for pagination URLs
def generate_page_url(page_num, current_args):
    """Generates URL for a specific page, preserving other query params."""
    args = current_args.copy()
    args['page'] = page_num
    return url_for('admin_index', **args)

# Register filters and globals
app.jinja_env.filters['numberformat'] = simple_number_format
app.jinja_env.filters['dateformat'] = format_datetime
app.add_template_global(generate_sort_url, name='sort_url')
app.add_template_global(generate_page_url, name='page_url') # Register page_url

# --- Data Fetching ---
def get_admin_index_data(args):
    """Fetches data required for the admin index page, handling filters and pagination."""
    conn = get_db_connection()
    if not conn:
        # Return default/empty data if connection fails
        return {
            'page_title': 'YOURLS Admin - DB Error',
            'total_urls': 0,
            'total_clicks': 0,
            'display_on_page': 0, 'max_on_page': 0, 'total_items': 0,
            'total_items_clicks': None,
            'search_sentence': 'Database connection error.',
            'links': [], 'page': 1, 'perpage': DEFAULT_PER_PAGE, 'total_pages': 1,
            'sort_by': DEFAULT_SORT_BY, 'sort_order': DEFAULT_SORT_ORDER,
            'search': '', 'search_in': 'keyword', 'filter': ''
        }

    context = {}
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)

        # --- Get Parameters ---
        try:
            page = int(args.get('page', '1'))
            if page < 1: page = 1
        except ValueError:
            page = 1

        try:
            perpage = int(args.get('perpage', str(DEFAULT_PER_PAGE)))
            if perpage < 1: perpage = DEFAULT_PER_PAGE
        except ValueError:
            perpage = DEFAULT_PER_PAGE

        sort_by = args.get('sort_by', DEFAULT_SORT_BY).lower()
        if sort_by not in VALID_SORT_COLUMNS:
            sort_by = DEFAULT_SORT_BY

        sort_order = args.get('sort_order', DEFAULT_SORT_ORDER).upper()
        if sort_order not in {'ASC', 'DESC'}:
            sort_order = DEFAULT_SORT_ORDER

        search = args.get('search', '').strip()
        search_in = args.get('search_in', 'keyword').lower()
        # TODO: Add validation for search_in against VALID_SEARCH_COLUMNS or 'all'

        # TODO: Implement other filters (clicks, date)
        filter_param = args.get('filter', '') # Example for future use

        # --- Build Query ---        
        where_clauses = []
        bind_params = {}

        search_sentence = ''
        if search:
            search_term_like = f"%{search}%"
            if search_in == 'all': # Based on YOURLS PHP logic
                where_clauses.append("CONCAT_WS('', keyword, url, title, ip) LIKE %(search)s")
                bind_params['search'] = search_term_like
                search_sentence = f"Searching for \"{search}\" in all fields."
            elif search_in in VALID_SEARCH_COLUMNS:
                # Use safe column name insertion (no user input directly in SQL structure)
                where_clauses.append(f"`{search_in}` LIKE %(search)s")
                bind_params['search'] = search_term_like
                search_sentence = f"Searching for \"{search}\" in {search_in}."
            else:
                 # Invalid search_in, maybe default to keyword or ignore?
                 where_clauses.append(f"`keyword` LIKE %(search)s")
                 bind_params['search'] = search_term_like
                 search_sentence = f"Searching for \"{search}\" in keyword (default)."

        # TODO: Add WHERE clauses for date filters, click filters here

        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
        order_by_sql = f"ORDER BY `{sort_by}` {sort_order}"

        # --- Execute Queries ---
        # Get total items matching the filter
        count_query = f"SELECT COUNT(*) as count FROM yourls_url WHERE {where_sql}"
        cursor.execute(count_query, bind_params)
        total_items_result = cursor.fetchone()
        total_items = total_items_result['count'] if total_items_result else 0

        # Calculate pagination
        total_pages = math.ceil(total_items / perpage) if total_items > 0 else 1
        if page > total_pages:
            page = total_pages # Adjust page if it exceeds total pages
        offset = (page - 1) * perpage

        # Get the links data for the current page
        data_query = f"SELECT keyword, url, title, timestamp, clicks FROM yourls_url WHERE {where_sql} {order_by_sql} LIMIT %(limit)s OFFSET %(offset)s"
        bind_params['limit'] = perpage
        bind_params['offset'] = offset
        cursor.execute(data_query, bind_params)
        links = cursor.fetchall()

        # --- Get Overall Stats (Could be cached later) ---
        cursor.execute("SELECT COUNT(*) as count, SUM(clicks) as clicks_sum FROM yourls_url")
        stats = cursor.fetchone()
        total_urls = stats['count'] if stats and stats['count'] is not None else 0
        total_clicks = stats['clicks_sum'] if stats and stats['clicks_sum'] is not None else 0

        # --- Prepare Context ---
        context = {
            'page_title': 'YOURLS Admin',
            'links': links,
            'total_urls': total_urls,
            'total_clicks': total_clicks,
            'total_items': total_items,
            'total_items_clicks': None, # TODO: Calculate clicks for filtered items if needed
            'page': page,
            'perpage': perpage,
            'total_pages': total_pages,
            'display_on_page': min(offset + 1, total_items),
            'max_on_page': min(offset + perpage, total_items),
            'sort_by': sort_by,
            'sort_order': sort_order,
            'search': search,
            'search_in': search_in,
            'search_sentence': search_sentence,
            'filter': filter_param # Pass filter back to template
        }

    except Error as e:
        print(f"Error fetching data: {e}")
        # Simplified error context
        context = {
            'page_title': 'YOURLS Admin - Error',
            'search_sentence': f'Database query error: {e}', 
            'links': [], 'total_urls': 0, 'total_clicks': 0,
            'total_items': 0, 'page': 1, 'perpage': DEFAULT_PER_PAGE, 'total_pages': 1,
            'sort_by': DEFAULT_SORT_BY, 'sort_order': DEFAULT_SORT_ORDER,
             'search': '', 'search_in': 'keyword', 'filter': ''
        }
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()
            # print("MySQL connection is closed") # Optional: for debugging

    return context

# --- Helper Functions (Validation/Sanitization - TODO: Improve these) ---
def sanitize_keyword(keyword):
    """Basic keyword sanitization (allows letters, numbers, dash, underscore)."""
    if not keyword:
        return None
    # Replace invalid characters - needs refinement based on YOURLS rules
    sanitized = re.sub(r'[^a-zA-Z0-9_-]', '', keyword)
    return sanitized if sanitized else None # Return None if empty after sanitization

def generate_next_keyword():
    """Generates the next sequential short keyword (base 36). Placeholder.
       Requires knowing the last used ID or keyword.
    """
    # This needs a proper implementation, likely querying the DB for the highest ID
    # or using a dedicated sequence/counter.
    # For now, returning None to force manual keyword or fail.
    # A simple approach might involve converting MAX(id) to base 36.
    # Or just using a random string for simplicity initially.
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))

# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
def admin_index():
    """Renders the main admin page and handles link addition."""
    if request.method == 'POST':
        # Handle the form submission
        long_url = request.form.get('url', '').strip()
        custom_keyword = request.form.get('keyword', '').strip()
        title = request.form.get('title', '').strip()

        if not long_url:
            flash('Error: URL is required.', 'error')
        else:
            # Basic URL validation (starts with http/https)
            if not long_url.lower().startswith(('http://', 'https://')):
                flash('Error: URL must start with http:// or https://.', 'error')
            else:
                keyword_to_insert = sanitize_keyword(custom_keyword)
                if not keyword_to_insert:
                    # If no custom keyword or invalid, generate one (placeholder)
                    keyword_to_insert = generate_next_keyword()
                    # TODO: Check if generated keyword exists and retry if needed

                if not keyword_to_insert:
                     flash('Error: Could not generate a valid keyword.', 'error')
                else:
                    # Get IP address
                    ip_address = request.remote_addr
                    
                    # Attempt to insert into DB
                    conn = get_db_connection()
                    if not conn:
                        flash('Error: Database connection failed.', 'error')
                    else:
                        cursor = None
                        try:
                            cursor = conn.cursor()
                            insert_query = """
                            INSERT INTO yourls_url (keyword, url, title, timestamp, ip, clicks)
                            VALUES (%(keyword)s, %(url)s, %(title)s, NOW(), %(ip)s, 0)
                            """
                            data = {
                                'keyword': keyword_to_insert,
                                'url': long_url,
                                'title': title if title else None, # Use None for empty title
                                'ip': ip_address
                            }
                            cursor.execute(insert_query, data)
                            conn.commit()
                            flash(f'Short URL created: {keyword_to_insert}', 'success')
                        except mysql.connector.Error as err:
                            conn.rollback() # Rollback on error
                            if err.errno == 1062: # Duplicate entry error code
                                flash(f'Error: Keyword \"{keyword_to_insert}\" already exists.', 'error')
                            else:
                                flash(f'Database Error: {err}', 'error')
                                print(f"DB Error: {err}")
                        finally:
                            if cursor:
                                cursor.close()
                            if conn and conn.is_connected():
                                conn.close()

        # Redirect back to the index page after POST to avoid re-submission on refresh
        return redirect(url_for('admin_index'))

    # --- Handle GET request (as before) ---
    context = get_admin_index_data(request.args)
    return render_template('admin_index.html', **context)

@app.route('/<string:keyword>')
def redirect_link(keyword):
    """Handles the redirection of a short keyword to its original URL."""
    # Sanitize the keyword first
    # Note: YOURLS uses a specific character set, adapt sanitize_keyword if needed.
    sanitized_keyword = sanitize_keyword(keyword) 
    
    if not sanitized_keyword:
        # If sanitization results in empty string or invalid chars were used
        return abort(404)

    conn = get_db_connection()
    if not conn:
        # Service unavailable if DB is down
        # Maybe show a custom error page later?
        return abort(503, description="Database connection failed") 

    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Find the URL
        select_query = "SELECT url FROM yourls_url WHERE keyword = %(keyword)s"
        cursor.execute(select_query, {'keyword': sanitized_keyword})
        result = cursor.fetchone()
        
        if result and result['url']:
            original_url = result['url']
            
            # Update click count (important to do this before redirecting)
            try:
                update_query = "UPDATE yourls_url SET clicks = clicks + 1 WHERE keyword = %(keyword)s"
                # Need a separate cursor or ensure the previous one is done?
                # Using the same cursor should be fine here.
                cursor.execute(update_query, {'keyword': sanitized_keyword})
                conn.commit()
            except Error as update_err:
                # Log the error, but still redirect if URL was found
                print(f"DB Error (Update Clicks): {update_err}")
                conn.rollback() # Rollback the failed click update

            # Perform the redirect
            # Use 301 for permanent redirect, as is common for URL shorteners
            return redirect(original_url, code=301)
        else:
            # Keyword not found in the database
            return abort(404)

    except Error as e:
        print(f"DB Error (Redirect): {e}")
        # Generic server error if something went wrong during lookup
        return abort(500, description="Database query error") 
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

# --- Main execution (remains the same) ---
if __name__ == '__main__':
    app.run(debug=True, port=5000)