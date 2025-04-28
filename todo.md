# YOURLS Python Adapter - TODO List

## Tasks Requiring YOURLS PHP Source Code Analysis

*These tasks likely require referencing the original PHP code for accurate implementation, compatibility, or understanding specific logic/formats.*

- [ ] **Keyword Generation:** Implement YOURLS-compliant sequential keyword generation (e.g., base36) in `generate_next_keyword`. (Requires knowing `yourls_get_next_keyword()` logic).
- [ ] **Keyword Sanitization:** Refine `sanitize_keyword` to exactly match YOURLS allowed characters and rules. (Requires knowing `yourls_sanitize_keyword()` logic).
- [ ] **"Share" Feature:** Add the "Share" button to the links table and implement the corresponding share box functionality (HTML, JS). (Requires analysis of `yourls_share_box()`, `share.js`, `common.js`).
- [ ] **"Tools" Page:** Create the `/tools` route and `tools.html` template, replicating the bookmarklet generator and potentially other tools. (Requires analysis of `tools.php` for bookmarklet code generation).
- [ ] **API Implementation:** Implement the YOURLS API endpoints in Python. (Requires detailed analysis of `yourls-api.php` for parameters, formats, auth).
- [ ] **(Optional) "Plugins" Page:** Implement plugin management functionality (listing, activation/deactivation - complex). (Requires deep understanding of YOURLS plugin architecture).
- [ ] **AJAX Operations (for compatibility):** Refactor Add, Edit, Delete actions to use AJAX compatible with original YOURLS JS, if aiming for full JS compatibility. (Requires analysis of `admin-ajax.php` and related JS).
- [ ] **JavaScript Parity:** Ensure full compatibility and initialization for features from `common.js`, `insert.js`, `share.js`, etc. (Requires detailed analysis of original JS and potentially PHP interaction).
- [ ] **(Partially) i18n Support:** Review original `.po`/`.mo` files and PHP functions (`yourls__()`, `yourls_n()`) to ensure consistency if implementing i18n.
- [ ] **(Partially) GeoIP Lookup:** Review original PHP code to see which specific GeoIP database/library is used, if aiming for exact replication.

## Tasks Implementable with Standard Python/Flask Practices

*These tasks can generally be implemented using standard web development practices and Python/Flask libraries without needing to reference the original YOURLS PHP code.* 

### Security Enhancements

- [ ] **Password Hashing:** Re-implement password hashing using `werkzeug.security` (or `passlib`) instead of plain text comparison.
- [ ] **CSRF Protection:** Add CSRF tokens to all forms handling POST requests (Login, Add, Edit, Delete) using Flask-WTF or similar.

### Core Functionality

- [ ] **GeoIP Lookup (Basic):** Integrate `geoip2` library and GeoLite2 database to log country codes and display them on the stats page. (Standard Python implementation).

### UI/UX & JavaScript

- [ ] **AJAX Operations (new implementation):** Refactor Add/Edit/Delete to use *new* AJAX endpoints defined in Flask, potentially requiring new JS code.
- [ ] **i18n Support (Basic):** Implement internationalization using Flask-Babel or similar for UI text using new translation files.
- [ ] **Custom Error Pages:** Create styled templates for common errors (404, 500, 503) using Flask's `@app.errorhandler`.

### Code Quality & Refinement

- [ ] **Automated Testing:** Write unit and integration tests for the Flask application and helper functions.
- [ ] **Configuration Management:** Improve configuration handling if needed (beyond basic `.env`).
- [ ] **Error Handling:** Enhance database and application-level error handling and logging.
- [ ] **Version Display:** Show the application version (if defined) in the footer.
- [ ] **Code Cleanup:** Refactor code, remove unused placeholders, improve comments. 