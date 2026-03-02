# Lab 4 Answers — Secure Code Review Clinic



## Task A — Quick dataflow map
- inputs → validation (if any) → sink
- GET q→ none→ app.search_tickets() builds SQL with f-string → SQL execution
- POST comment (+POST ticket_id) → none →  app.add_comment() inserts comment_html →  later HTML rendering
- POST ticket_id → int?→ view_ticket() SQL param query → DB read
- GET file → unquote() only →  files.download_attachment() open(path) → file open/download
- GET host →  none →  ops.ping_host() builds shell cmd → os.system() OS command execution
- GET url →  none →  integrations.fetch_webhook() →  requests.get() →  HTTP fetch (SSRF) +TLS disabled
- X-User/X-Role headers →  none → current_user() →  used for comment author/"viewer" identity → authN/authZ decisions
- login(name, password) →  none →  md5_hash_password() →  compare stored hash+
- make_session_token() → password hasing +session token generation
- utils.parse_filters(filter_expr) → none →  eval() →  code execution*

## Task B — Findings (Defects → Mitigations)
Provide at least **10**.

| # | File:Lines | Defect (CWE) | Why | Exploit scenario | Severity | Mitigation(s) | Patch? | Patch summary |
|---|------------|--------------|-----|------------------|----------|---------------|--------|---------------|
| 1 |app.py:45–61|CWE-89 SQL Injection|q is concatenated into SQL with an f-string, so attacker-controlled input reaches SQL execution.|?q+% OR 1=1-- returns all tickets (or worse, depending on DB settings). |H (direct DB compromise)|Use parameterized query with LIKE ? and escape wildcards; length-limit q.|Yes|Rewrote search to ... LIKE ? ESCAPE '\' with wildcard escaping + max length.|
| 2 |utils.py:11–48| CWE-94 Code Injection (eval)|eval(filter_expr) executes attacker input as code (even with _builtins_ stripped, it’s still dangerous and can be bypassed).|Attacker sends a crafted expression to read objects / crash / potentially escape sandbox.|H|Replace with json.loads or strict parser; validate types/keys.|Yes| Replaced eval with json.loads + optional safe ast.literal_eval and type checks.|
| 3 |ops.py:10–36|CWE-78 OS Command Injection|host is interpolated into a shell command executed by os.system().|host=8.8.8.8;cat /etc/passwd runs attacker command.|H|Validate host strictly; use subprocess.run([...], shell=False); avoid temp file redirection.|Yes|Added strict hostname/IP validation + subprocess.run capture output.|
| 4 |integrations.py:40–57|CWE-295 Improper Certificate Validation| requests.get(..., verify=False) disables TLS verification → MITM.| Attacker on same network intercepts webhook response and injects content.|H|Enable verify=True; set timeouts; consider allowlist.|Yes|Turned on verification, added timeout, and blocked non-HTTPS by default.|
| 5 |integrations.py:10–57|CWE-918 SSRF|Untrusted url is fetched server-side with no validation, allowing access to internal services.|url=http://127.0.0.1:... hits internal admin endpoints or cloud metadata.|H| Allowlist schemes/domains; block private/loopback/link-local IPs; limit redirects.|Yes|Added URL parsing + DNS resolution + private-IP blocking + redirect limits.|
| 6 |files.py:8–35|CWE-22 Path Traversal|filename is joined to UPLOAD_DIR without normalization/containment checks.|file=../../../../etc/passwd reads arbitrary files.|H|Normalize path, ensure it stays under UPLOAD_DIR; reject separators; use allowlist.|Yes|Added safe_join_uploads() realpath containment check; reject bad filenames.|
| 7 |files.py:29–35| CWE-209 Information Exposure|Returns full filesystem path in API response.|User learns server layout, aiding later attacks.|M|Don’t return absolute paths; return logical filename/id only.|Yes|Response now returns {"filename": ..., "preview_bytes": ...} only.|
| 8 |app.py:24–39|CWE-287 Improper Authentication|“Auth” is derived from X-User/X-Role headers (attacker can set them).|Request with X-Role: admin becomes “admin”.|H|Use server-side session/cookies; verify signed token; ignore client role header.|YES|Added signed session tokens and get_authenticated_user() that verifies token.|
| 9 |app.py:40–44, 80–94|CWE-285 Improper Authorization|reset_password() does not check role/ownership at all.|Any user resets any account password.|H|Require admin or same-user; enforce authz checks.|YES|Added require_admin() and checks before reset.|
|10 |app.py:95–111|CWE-79 Stored XSS|comment_html is stored as HTML. If later rendered, attacker-controlled HTML/JS executes.|Post <script>...</script> as comment; victims viewing ticket run JS.|H|Store plain text; escape on render; sanitize if HTML is required.|YES|Renamed to comment_text behavior: escape via html.escape() before storing.|
