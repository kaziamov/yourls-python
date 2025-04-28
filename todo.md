# YOURLS Python Adapter - TODO List

## Security Enhancements

- [ ] **Password Hashing:** Re-implement password hashing using `werkzeug.security` (or `passlib`) instead of plain text comparison.
- [ ] **CSRF Protection:** Add CSRF tokens to all forms handling POST requests (Login, Add, Edit, Delete) using Flask-WTF or similar.

## Core Functionality

- [ ] **Keyword Generation:** Implement YOURLS-compliant sequential keyword generation (e.g., base36) in `generate_next_keyword`.
- [ ] **Keyword Sanitization:** Refine `sanitize_keyword` to exactly match YOURLS allowed characters and rules.
- [ ] **GeoIP Lookup:** Integrate `geoip2` library and GeoLite2 database to log country codes and display them on the stats page.
- [ ] **"Share" Feature:** Add the "Share" button to the links table and implement the corresponding share box functionality (HTML, JS).
- [ ] **"Tools" Page:** Create the `/tools` route and `tools.html` template, replicating the bookmarklet generator and potentially other tools.
- [ ] **API Implementation:** Implement the YOURLS API endpoints in Python.
- [ ] **(Optional) "Plugins" Page:** Implement plugin management functionality (listing, activation/deactivation - complex).

## UI/UX & JavaScript

- [ ] **AJAX Operations:** Refactor Add, Edit, Delete actions to use AJAX requests for a smoother UX without full page reloads.
- [ ] **JavaScript Parity:** Ensure full compatibility and initialization for features from `common.js`, `insert.js`, `share.js`, `clipboard.min.js`, `jquery.cal.js` (e.g., dynamic date field visibility, clipboard button, etc.).
- [ ] **i18n Support:** Implement internationalization using Flask-Babel or similar for UI text.
- [ ] **Custom Error Pages:** Create styled templates for common errors (404, 500, 503) instead of default abort pages.

## Code Quality & Refinement

- [ ] **Automated Testing:** Write unit and integration tests for the Flask application and helper functions.
- [ ] **Configuration Management:** Improve configuration handling if needed (beyond basic `.env`).
- [ ] **Error Handling:** Enhance database and application-level error handling and logging.
- [ ] **Version Display:** Show the application version (if defined) in the footer.
- [ ] **Code Cleanup:** Refactor code, remove unused placeholders, improve comments. 