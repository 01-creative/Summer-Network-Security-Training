# Flask User Management System

A security-hardened Flask web application for user management, developed as part of a cybersecurity training course.

## Features

- User login/logout with session management
- Password hashing (scrypt via Werkzeug)
- CSRF protection on all POST endpoints
- Rate limiting (IP + username dual-dimension, dual-window)
- Mandatory password change on first login
- Profile editing with input sanitization
- Time-based greeting

## Quick Start

```bash
export FLASK_SECRET_KEY="$(python -c 'import os; print(os.urandom(32).hex())')"
export INIT_PWD_ADMIN="YourStrongPassword@2026"
export INIT_PWD_ALICE="YourStrongPassword@2026"
pip install -r requirements.txt
python app.py
```

## Security

This project has undergone four rounds of white-box audit, black-box penetration testing, and automated iterative testing.

## License

Educational project.
