DROP TABLE IF EXISTS tickets;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS comments;

CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL);
CREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL);
CREATE TABLE comments (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL, author TEXT NOT NULL, comment_html TEXT NOT NULL);

INSERT INTO users(username, password_hash, role) VALUES
('alice', '5f4dcc3b5aa765d61d8327deb882cf99', 'student'),
('bob',   '202cb962ac59075b964b07152d234b70', 'staff');

INSERT INTO tickets(owner, subject, body, status) VALUES
('alice', 'Cannot login', 'I forgot my password. Please help.', 'open'),
('alice', 'Upload issue', 'My screenshot upload fails.', 'open'),
('bob',   'Internal note', 'Staff-only ticket example.', 'open');
