# YOURLS Python Adapter - TODO List

## Tasks Requiring YOURLS PHP Source Code Analysis

*These tasks likely require referencing the original PHP code for accurate implementation, compatibility, or understanding specific logic/formats.*

- [x] **API Implementation:** Implement the YOURLS API endpoints in Python. (Requires detailed analysis of `yourls-api.php` for parameters, formats, auth). Basic implementation done in `src/app.py:/api`. Potential improvements: signature auth, XML format, parameter parity.
- [ ] **(Optional) Plugin System Implementation (Complex):** Replicate YOURLS plugin architecture.
    - [ ] **Plugin Discovery & Metadata:** Define plugin structure (e.g., Python module/package in `user/plugins`), implement discovery and metadata reading.
    - [ ] **Plugin Activation State:** Implement storage for active plugins (e.g., DB table/option).
    - [ ] **Admin UI - Plugin Management:** Create `/admin/plugins` page (list, activate, deactivate).
    - [ ] **Hook System (Core):** Implement a Pythonic hook/signal system (`add_action`, `do_action`, `add_filter`, `apply_filters` equivalents). Define core hooks.
    - [ ] **Plugin Loading:** Implement dynamic loading of *active* plugin code on app startup to register hooks.
    - [ ] **(Optional) Plugin Admin Pages:** Allow plugins to register custom admin interface pages.
- [ ] **AJAX Operations (for compatibility):** Refactor Add, Edit, Delete actions to use AJAX compatible with original YOURLS JS, if aiming for full JS compatibility. (Requires analysis of `admin-ajax.php` and related JS).
- [ ] **JavaScript Parity:** Ensure full compatibility and initialization for features from `common.js`, `insert.js`, `share.js`, etc. (Requires detailed analysis of original JS and potentially PHP interaction).
- [ ] **(Partially) i18n Support:** Review original `.po`/`.mo` files and PHP functions (`yourls__()`, `yourls_n()`) to ensure consistency if implementing i18n.
- [x] **"Tools" Page:** Create the `/tools` route and `tools.html` template, replicating the bookmarklet generator and potentially other tools. (Requires analysis of `tools.php` for bookmarklet code generation). UPD: Основная функциональность страницы /tools в части генерации и обработки стандартных/мгновенных/простых/пользовательских букмарклетов реализована. Социальные букмарклеты требуют доработки (Added social share handling to `/` endpoint (`add_link_endpoint`) based on `tools.php` logic.)

## Tasks Implementable with Standard Python/Flask Practices

*These tasks can generally be implemented using standard web development practices and Python/Flask libraries without needing to reference the original YOURLS PHP code.* 

### Security Enhancements

- [ ] **Password Hashing:** Re-implement password hashing using `werkzeug.security` (or `passlib`) instead of plain text comparison.
- [x] **CSRF Protection:** Add CSRF tokens to all forms handling POST requests (Login, Add, Edit, Delete) using Flask-WTF or similar. (Basic nonce system implemented for AJAX in `src/app.py::admin_ajax_handler`)

### Core Functionality

- [ ] **(Partially Done) GeoIP Lookup (Basic):** Integrate `geoip2` library and GeoLite2 database to log country codes and display them on the stats page. (Standard Python implementation). (Implemented GeoIP lookup, click logging with country code in `redirect_link_get`, and country stats fetching in `link_stats_get`. Requires `GeoLite2-Country.mmdb`, `.env` config, `yourls_log` table, and template updates for `link_stats.html`.)

### UI/UX & JavaScript

- [ ] **(Partially Done) AJAX Operations (new implementation):** Refactor Add/Edit/Delete to use *new* AJAX endpoints defined in Flask, potentially requiring new JS code. (Implemented `/admin-ajax` endpoint in `src/app.py` compatible with original `insert.js` actions: add, edit_display, edit_save, delete. Needs testing and `ajaxurl` definition in template.)
- [ ] **(Partially Done) JavaScript Parity:** Ensure full compatibility and initialization for features from `common.js`, `insert.js`, `share.js`, etc. (Analyzed JS files. Implemented necessary backend in `/admin-ajax`. Requires testing, `ajaxurl` definition, and ensuring dependencies like notifyBar/ClipboardJS are loaded.)
- [ ] **Define `ajaxurl` JavaScript variable:** Define the global `ajaxurl` variable in the admin base template, pointing to the `/admin-ajax` endpoint.
- [ ] **i18n Support (Basic):** Implement internationalization using Flask-Babel or similar for UI text using new translation files.
- [ ] **Custom Error Pages:** Create styled templates for common errors (404, 500, 503) using Flask's `@app.errorhandler`.

### Code Quality & Refinement

- [ ] **Implement `url_truncate` Jinja2 filter:** Add the missing `url_truncate` filter used in `table_row.html` to `app.py`.
- [ ] **Automated Testing:** Write unit and integration tests for the Flask application and helper functions.
- [ ] **Configuration Management:** Improve configuration handling if needed (beyond basic `.env`).
- [ ] **Error Handling:** Enhance database and application-level error handling and logging.
- [ ] **Version Display:** Show the application version (if defined) in the footer.
- [ ] **Code Cleanup:** Refactor code, remove unused placeholders, improve comments. 