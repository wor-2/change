CREATE TABLE IF NOT EXISTS users(
  id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT, email TEXT, phone TEXT,
  role TEXT NOT NULL DEFAULT 'requester',   -- requester|cab|technical|business|approver|admin
  password_hash TEXT);
CREATE SEQUENCE IF NOT EXISTS change_seq;
CREATE TABLE IF NOT EXISTS change_requests(
  id SERIAL PRIMARY KEY, change_no TEXT UNIQUE NOT NULL, title TEXT NOT NULL, application TEXT NOT NULL,
  environment TEXT NOT NULL, change_type TEXT NOT NULL, priority TEXT DEFAULT 'Medium', description TEXT NOT NULL,
  planned_start TIMESTAMP NOT NULL, planned_end TIMESTAMP NOT NULL, stakeholders TEXT,
  status TEXT NOT NULL DEFAULT 'SUBMITTED',
  requester_id INT REFERENCES users(id), assigned_team TEXT, approver_id INT REFERENCES users(id), triage_notes TEXT,
  business_impact TEXT, technical_impact TEXT, affected_services TEXT, implementation_plan TEXT,
  approval_comment TEXT, execution_notes TEXT, verified BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT now(), updated_at TIMESTAMP DEFAULT now(), closed_at TIMESTAMP);
CREATE TABLE IF NOT EXISTS attachments(
  id SERIAL PRIMARY KEY, change_id INT REFERENCES change_requests(id) ON DELETE CASCADE,
  filename TEXT, stored_name TEXT, stage TEXT, uploaded_at TIMESTAMP DEFAULT now());
CREATE TABLE IF NOT EXISTS history(
  id SERIAL PRIMARY KEY, change_id INT REFERENCES change_requests(id) ON DELETE CASCADE,
  actor TEXT, action TEXT, comment TEXT, created_at TIMESTAMP DEFAULT now());
CREATE TABLE IF NOT EXISTS notifications(
  id SERIAL PRIMARY KEY, change_id INT, channel TEXT, recipient TEXT, message TEXT, status TEXT,
  created_at TIMESTAMP DEFAULT now());
