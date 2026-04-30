# 🔐 Secure Data Directory (PHP)

A **secure, modern file directory system** built in PHP that provides controlled access to files with authentication, protection mechanisms, and an integrated document viewer.  
Based on your implementation.

---

## 🚀 Features

### 🔒 Security First
- Secure PHP sessions (HTTPOnly, SameSite, strict mode)
- CSRF protection with token validation
- Password hashing using **Argon2ID**
- Session fixation prevention (session ID regeneration)
- Rate limiting to prevent brute-force attacks
- Auto session expiry (30 minutes)
- Hardened security headers:
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`

---

### 🔑 Authentication System
- Password-protected directory
- Smart lockout mechanism:
  - 5 failed attempts → 5-minute lock
  - 10 failed attempts → 24-hour lock
- Secure logout with session destruction

---

### 📂 File Management
- Recursive file search across directories
- File filtering and exclusion support
- Sanitized user input
- Relative path handling

---

### 🔍 Smart Search
- Search files by name
- Minimum 3-character validation
- Input sanitization using regex

---

### 📄 Built-in Document Viewer

Supports:
- PDF → Google Docs Viewer
- Office Files → Microsoft Office Viewer

Supported formats:
- pdf, doc, docx, xls, xlsx, ppt, pptx, odt, ods, odp

---

### 🎨 Modern UI/UX
- Fully responsive design (mobile + desktop)
- Sidebar navigation system
- Smooth animations and transitions
- File-type icons with color coding
- Modal-based document preview
- Skeleton loading animation

---

## 🛠️ Installation

### 1. Clone Repository
```bash
git clone https://github.com/psvineet/web-directory-search.git
```

### 2. Move to Server Directory
```bash
cd web-directory-search
```

Place inside:
- Apache → /var/www/html
- XAMPP → htdocs

---

### 3. Configure Password

Generate secure hash:
```bash
php -r "echo password_hash('yourpassword', PASSWORD_ARGON2ID);"
```

Replace in code:
```php
$hashedPassword = 'your_generated_hash_here';
```
**Default - 1234**

---

### 4. Run Project

Open in browser:
```
http://localhost/your-folder/
```

---

## ⚙️ Configuration

### 🔧 Excluded Files
```php
$excludedFiles = ['.htaccess', 'config.php', 'settings.php'];
```

### 📁 Excluded Directories
```php
$excludedDirs = ['.git', 'node_modules'];
```

---

## 🔐 Security Highlights

| Feature | Implementation |
|--------|--------------|
| Password Storage | Argon2ID Hashing |
| CSRF Protection | Token-based |
| Session Security | Regeneration + strict mode |
| Rate Limiting | Session-based |
| XSS Prevention | Output escaping |
| Input Sanitization | Regex filtering |

---

## 📸 Screens Overview

### Login Page
- Password input with visibility toggle
- Error handling and lock state

### Dashboard
- File search interface
- Sidebar status display

### Viewer Modal
- Embedded document preview
- Retry and open-in-new-tab options

---

## ⚠️ Important Notes

- Default password must be changed before deployment
- Use HTTPS in production
- Set proper file permissions on server

---

## 📌 Use Cases

- Secure internal file system
- Private document storage
- Admin-only directory browser
- Lightweight document management system

---


## 📜 License

This project is open-source under MIT License.

---

## ⭐ Support

If you found this useful:
- Star the repository
- Share with others
