"""
DBMS Project - Pure Python Desktop GUI (Tkinter)
--------------------------------------------------
A complete frontend written entirely in Python using Tkinter - no HTML,
CSS, or JavaScript anywhere. Feature-matches the website version:
  - Login / Register screen (shared APP_USERS table, same as the website)
  - Per-user table isolation (your tables are prefixed with your username,
    so you only ever see your own tables - same logic as the Flask app)
  - Collapsible sidebar with color-coded categories: Table, Insert Data,
    Account, Behind the Scenes
  - A Query Log viewer under "Behind the Scenes" showing every SQL
    statement that actually ran

Requirements:
    pip install oracledb werkzeug

Run with:
    python gui_app.py
"""

import tkinter as tk
from tkinter import ttk, messagebox
import oracledb
import re
import math
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- ORACLE CONNECTION SETUP ----------------
oracledb.init_oracle_client(
    lib_dir=r"C:\Oracle\instantclient-basic-windows.x64-23.26.3.0.0\instantclient_23_26"
)

DB_USER = "User_Name" #replace with your Oracle DB username
DB_PASSWORD = "Password" #replace with your Oracle DB password
DB_DSN = "localhost/xe"

COLUMN_TYPES = [
    "VARCHAR2(255)", "VARCHAR2(100)", "VARCHAR2(50)",
    "NUMBER", "NUMBER(10,2)", "DATE", "TIMESTAMP", "CHAR(1)", "FLOAT", "CLOB"
]
COLUMN_CONSTRAINTS = ["", "PRIMARY KEY", "NOT NULL", "UNIQUE"]
IDENTIFIER_PATTERN = re.compile(r'^[A-Za-z][A-Za-z0-9_]*$')

QUERY_LOG = []
LOGGING_ENABLED = True  # toggled via the Query Log panel's on/off button


ORACLE_ERROR_TRANSLATIONS = {
    "ORA-00904": "One of the column names you used doesn't exist or isn't allowed (it might be a reserved SQL word like NOT, DATE, or ORDER).",
    "ORA-00942": "That table doesn't exist (it may have been deleted, or the name is misspelled).",
    "ORA-00955": "A table or object with that name already exists.",
    "ORA-00001": "That value already exists and must be unique - duplicate entry not allowed.",
    "ORA-01400": "One of the required fields was left empty.",
    "ORA-01722": "One of the values isn't a valid number for that column.",
    "ORA-01858": "One of the values isn't a valid date for that column.",
    "ORA-01861": "A date/time value wasn't in the expected format (expected YYYY-MM-DD, e.g. 2026-06-03).",
    "ORA-01017": "Incorrect username or password.",
    "ORA-02291": "That value doesn't match anything in the related table (a foreign key constraint failed).",
    "ORA-02292": "This row can't be deleted because other data still depends on it.",
    "ORA-00936": "The request is missing something it needs (a column, value, or condition).",
    "ORA-00957": "A column name was used more than once.",
    "ORA-12899": "One of the values you entered is too long for that column.",
    "ORA-02275": "That name conflicts with something already used on this table.",
    "DPY-6005": "Couldn't connect to the database - check that Oracle is running.",
    "DPY-4011": "The database connection was lost.",
}


def friendly_error(raw_message):
    """Turns a raw Oracle/oracledb error into a short plain-English sentence.
    Falls back to the original message (trimmed) if the error code isn't one
    we recognize, so nothing important ever gets hidden."""
    for code, plain_english in ORACLE_ERROR_TRANSLATIONS.items():
        if code in raw_message:
            return plain_english
    # Unrecognized error - still clean it up a little rather than dumping
    # the full multi-line Oracle traceback text.
    first_line = raw_message.strip().split("\n")[0]
    return first_line if len(first_line) <= 120 else first_line[:117] + "..."


def get_connection():
    return oracledb.connect(user=DB_USER, password=DB_PASSWORD, dsn=DB_DSN)


def log_query(action, sql, params=None):
    if not LOGGING_ENABLED:
        return
    QUERY_LOG.append({
        "action": action,
        "sql": sql,
        "params": [str(p) for p in params] if params else [],
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })


def is_valid_identifier(name):
    return bool(IDENTIFIER_PATTERN.match(name))


def ensure_users_table():
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM user_tables WHERE table_name = 'APP_USERS'")
        if not cursor.fetchone()[0]:
            cursor.execute("""
                CREATE TABLE APP_USERS (
                    username VARCHAR2(50) PRIMARY KEY,
                    password_hash VARCHAR2(255)
                )
            """)
            conn.commit()
    finally:
        cursor.close()
        conn.close()


def register_user(username, password):
    if not is_valid_identifier(username):
        return False, "Username must start with a letter and contain only letters/numbers/underscore"
    if len(password) < 4:
        return False, "Password too short"

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username FROM APP_USERS WHERE username = :1", [username])
        if cursor.fetchone():
            return False, "Username already exists"
        pw_hash = generate_password_hash(password)
        cursor.execute("INSERT INTO APP_USERS (username, password_hash) VALUES (:1, :2)", [username, pw_hash])
        conn.commit()
        return True, "Registered successfully. Please log in."
    finally:
        cursor.close()
        conn.close()


def verify_login(username, password):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT password_hash FROM APP_USERS WHERE username = :1", [username])
        row = cursor.fetchone()
        if not row or not check_password_hash(row[0], password):
            return False, "Invalid username or password"
        return True, "Login successful"
    finally:
        cursor.close()
        conn.close()


def change_password(username, new_password):
    if len(new_password) < 4:
        return False, "Password too short"
    conn = get_connection()
    cursor = conn.cursor()
    try:
        new_hash = generate_password_hash(new_password)
        cursor.execute("UPDATE APP_USERS SET password_hash = :1 WHERE username = :2", [new_hash, username])
        if cursor.rowcount == 0:
            conn.rollback()
            return False, "No account found with that username."
        conn.commit()
        return True, "Password updated successfully."
    finally:
        cursor.close()
        conn.close()


def delete_account(username, prefix, password):
    """Verifies the password, drops every table belonging to this user
    (matching their prefix), then removes the account itself. All done in
    one connection so it either all succeeds or all rolls back together."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT password_hash FROM APP_USERS WHERE username = :1", [username])
        row = cursor.fetchone()
        if not row or not check_password_hash(row[0], password):
            return False, "Incorrect password."

        cursor.execute("SELECT table_name FROM user_tables WHERE table_name LIKE :1", [prefix + '%'])
        user_tables = [r[0] for r in cursor.fetchall()]
        for table_name in user_tables:
            cursor.execute(f"DROP TABLE {table_name}")

        cursor.execute("DELETE FROM APP_USERS WHERE username = :1", [username])
        conn.commit()
        return True, "Account and all associated tables deleted."
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


def create_table(prefix, table_name, columns):
    col_defs = []
    for name, col_type, constraint in columns:
        definition = f"{name} {col_type}"
        if constraint:
            definition += f" {constraint}"
        col_defs.append(definition)

    full_name = prefix + table_name
    sql = f"CREATE TABLE {full_name} ({', '.join(col_defs)})"
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        log_query("CREATE TABLE", sql)
        return True, f"Table '{table_name}' created successfully."
    except Exception as e:
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


def rename_table(prefix, old_name, new_name):
    full_old = prefix + old_name
    full_new = prefix + new_name
    sql = f"RENAME {full_old} TO {full_new}"
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        log_query("RENAME TABLE", sql)
        return True, f"Table renamed to '{new_name}'."
    except Exception as e:
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


def add_column(prefix, table_name, col_name, col_type):
    full_name = prefix + table_name
    sql = f"ALTER TABLE {full_name} ADD {col_name} {col_type}"
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        log_query("ADD COLUMN", sql)
        return True, f"Column '{col_name}' added."
    except Exception as e:
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


def rename_column(prefix, table_name, old_col, new_col):
    full_name = prefix + table_name
    sql = f"ALTER TABLE {full_name} RENAME COLUMN {old_col} TO {new_col}"
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        log_query("RENAME COLUMN", sql)
        return True, f"Column renamed to '{new_col}'."
    except Exception as e:
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


def drop_table(prefix, table_name):
    full_name = prefix + table_name
    sql = f"DROP TABLE {full_name}"
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        log_query("DROP TABLE", sql)
        return True, f"Table '{table_name}' dropped."
    except Exception as e:
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


def insert_row(prefix, table_name, column_names, values, column_types=None):
    column_types = column_types or {}
    full_name = prefix + table_name
    placeholders = ", ".join(
        build_placeholder(i + 1, column_types.get(col, ""), values[i])
        for i, col in enumerate(column_names)
    )
    sql = f"INSERT INTO {full_name} ({', '.join(column_names)}) VALUES ({placeholders})"
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql, values)
        conn.commit()
        log_query("INSERT", sql, values)
        return True, "Row inserted successfully."
    except Exception as e:
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


def get_all_rows(prefix, table_name):
    full_name = prefix + table_name
    sql = f"SELECT * FROM {full_name}"
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        columns = [col[0] for col in cursor.description]
        rows = cursor.fetchall()
        return True, columns, rows
    except Exception as e:
        return False, str(e), []
    finally:
        cursor.close()
        conn.close()


def get_table_names(prefix):
    sql = "SELECT table_name FROM user_tables WHERE table_name LIKE :1 ORDER BY table_name"
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql, [prefix + '%'])
        return [row[0][len(prefix):] for row in cursor.fetchall()]
    finally:
        cursor.close()
        conn.close()


def get_table_columns(prefix, table_name):
    """Like get_column_names, but also returns each column's data type -
    needed so DATE/TIMESTAMP columns can be given the right TO_DATE format
    instead of relying on Oracle's implicit (and often wrong) conversion."""
    full_name = (prefix + table_name).upper()
    sql = "SELECT column_name, data_type FROM user_tab_columns WHERE table_name = :1 ORDER BY column_id"
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql, [full_name])
        return [{"name": row[0], "type": row[1]} for row in cursor.fetchall()]
    finally:
        cursor.close()
        conn.close()


def build_placeholder(index, col_type, value):
    """Returns the correct bind placeholder for one column: plain :n for
    ordinary columns, or TO_DATE(:n, '<detected format>') for DATE/TIMESTAMP
    columns, so a typed date like '2026-06-03' or '2026-06-03 14:30' is
    parsed the way the user actually wrote it instead of Oracle guessing
    with its own default format (which is what caused ORA-01861)."""
    if col_type in ("DATE", "TIMESTAMP", "TIMESTAMP(6)") and value not in (None, ""):
        value_str = str(value)
        if ":" in value_str and value_str.count(":") >= 2:
            fmt = "YYYY-MM-DD HH24:MI:SS"
        elif ":" in value_str:
            fmt = "YYYY-MM-DD HH24:MI"
        else:
            fmt = "YYYY-MM-DD"
        return f"TO_DATE(:{index}, '{fmt}')"
    return f":{index}"


def get_column_names(prefix, table_name):
    full_name = (prefix + table_name).upper()
    sql = "SELECT column_name FROM user_tab_columns WHERE table_name = :1 ORDER BY column_id"
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql, [full_name])
        return [row[0] for row in cursor.fetchall()]
    finally:
        cursor.close()
        conn.close()


def update_rows(prefix, table_name, set_columns, set_values, where_columns, where_values, column_types=None):
    column_types = column_types or {}
    full_name = prefix + table_name
    set_clause = ", ".join(
        f"{col} = {build_placeholder(i + 1, column_types.get(col, ''), set_values[i])}"
        for i, col in enumerate(set_columns)
    )
    offset = len(set_columns)
    where_clause = " AND ".join(
        f"{col} = {build_placeholder(offset + i + 1, column_types.get(col, ''), where_values[i])}"
        for i, col in enumerate(where_columns)
    )
    sql = f"UPDATE {full_name} SET {set_clause} WHERE {where_clause}"
    bind_values = set_values + where_values

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql, bind_values)
        rows_affected = cursor.rowcount
        conn.commit()
        log_query("UPDATE", sql, bind_values)
        if rows_affected == 0:
            return False, "0 rows matched - check the Find Row values match exactly."
        return True, f"{rows_affected} row(s) updated."
    except Exception as e:
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


def get_bookings_in_range(prefix, table_name, start_col, end_col, date_from, date_to, use_duration=False):
    """Returns every (start_time, end_time) pair from the given table whose
    start_col falls within [date_from, date_to] (inclusive) - used to build
    the busy/free timetable grid.

    Some tables (like workout_sessions here) don't store a separate end-time
    column - only a start time plus a duration-in-minutes column. When
    use_duration is True, end_col is treated as that duration column, and the
    end time is computed in SQL as start_col + (duration minutes)."""
    full_name = prefix + table_name
    if use_duration:
        end_expr = f"{start_col} + ({end_col} / 1440)"  # 1440 minutes in a day
    else:
        end_expr = end_col

    sql = (f"SELECT {start_col}, {end_expr} FROM {full_name} "
           f"WHERE {start_col} >= TO_DATE(:1, 'YYYY-MM-DD') "
           f"AND {start_col} < TO_DATE(:2, 'YYYY-MM-DD') + 1")
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql, [date_from, date_to])
        rows = cursor.fetchall()
        log_query("SELECT (timetable)", sql, [date_from, date_to])
        return True, rows
    except Exception as e:
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


def delete_rows(prefix, table_name, where_columns, where_values, column_types=None):
    column_types = column_types or {}
    full_name = prefix + table_name
    where_clause = " AND ".join(
        f"{col} = {build_placeholder(i + 1, column_types.get(col, ''), where_values[i])}"
        for i, col in enumerate(where_columns)
    )
    sql = f"DELETE FROM {full_name} WHERE {where_clause}"

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql, where_values)
        rows_affected = cursor.rowcount
        conn.commit()
        log_query("DELETE", sql, where_values)
        if rows_affected == 0:
            return False, "0 rows matched - check the values match exactly."
        return True, f"{rows_affected} row(s) deleted."
    except Exception as e:
        return False, str(e)
    finally:
        cursor.close()
        conn.close()


# Toasts stay visible for 5 seconds each. (Note: you asked for "5 minutes" -
# assuming that was a slip of the tongue matching the website's identical
# 5-second toast design; change TOAST_DURATION_MS below if you really did
# mean minutes - 5 minutes = 300000.)
TOAST_DURATION_MS = 5000
MAX_TOASTS = 8


class ToastManager:
    """Shows small colored notifications pinned to the bottom-right corner of
    a window, stacking up to MAX_TOASTS at once (oldest removed first), each
    auto-dismissing after TOAST_DURATION_MS - replaces blocking messagebox
    popups so the user never has to click 'OK' to continue.

    The whole box has a FIXED width/height (never grows), so no matter how
    many toasts stack up it can never spread out and cover other buttons or
    dropdowns underneath - it stays confined to a small corner box."""

    BOX_WIDTH = 300
    BOX_HEIGHT = 260

    def __init__(self, window):
        self.window = window
        self.outer = tk.Frame(window, width=self.BOX_WIDTH, height=self.BOX_HEIGHT, bg=window.cget("bg"))
        self.outer.pack_propagate(False)  # keep the fixed size even as content changes
        # NOT placed yet - stays fully hidden (place_forget) until the first
        # toast actually appears, so this empty box never sits on top of and
        # cuts off other widgets (tables, forms, etc.) underneath it.
        self.toasts = []

    def show(self, message, success=True):
        if not self.toasts:
            self.outer.place(relx=1.0, rely=1.0, anchor="se", x=-10, y=-10)

        # Kept short and single-line (not wrapped) so up to MAX_TOASTS entries
        # reliably fit inside the fixed-height box - a packed widget that
        # doesn't fit can render outside its parent's bounds in Tkinter, which
        # is exactly the overlap problem this is meant to prevent.
        short_message = message if len(message) <= 55 else message[:52] + "..."

        bg = "#dcfce7" if success else "#fee2e2"
        fg = "#166534" if success else "#991b1b"
        toast = tk.Label(self.outer, text=short_message, bg=bg, fg=fg,
                          padx=8, pady=4, font=("Arial", 8), anchor="w")
        # Newest toast goes at the BOTTOM of the box (closest to the screen
        # corner), older ones get pushed up and drop off once the fixed
        # height is full.
        toast.pack(side="bottom", pady=2, fill="x")
        self.toasts.append(toast)

        if len(self.toasts) > MAX_TOASTS:
            oldest = self.toasts.pop(0)
            oldest.destroy()

        self.window.after(TOAST_DURATION_MS, lambda: self._remove(toast))

    def _remove(self, toast):
        if toast in self.toasts:
            self.toasts.remove(toast)
        try:
            toast.destroy()
        except tk.TclError:
            pass  # already destroyed (e.g. window closed)

        if not self.toasts:
            self.outer.place_forget()  # fully hide again - nothing left to show


class CustomCursor:
    """Replaces the OS mouse cursor with two custom shapes while the mouse is
    over this app's window:
      - an inner DOT that snaps exactly to the real mouse position every frame
      - an outer RING that eases toward the dot's position with a short delay,
        so it visibly "catches up" rather than moving instantly

    The ring is tethered: it is mathematically clamped so it can never drift
    farther than RING_RADIUS pixels from the dot. Because of that tether, the
    moment the mouse stops moving, the easing keeps pulling the ring inward
    until it settles back exactly centered on the dot - it can never end up
    stuck off to one side.

    Implementation note: Tkinter has no built-in animated/custom cursor, so
    this fakes one using two small always-on-top windows that continuously
    reposition themselves to follow the mouse, using Windows' -transparentcolor
    trick so only the drawn circle is visible (everything else is see-through).
    """

    DOT_RADIUS = 5
    RING_RADIUS = 14      # also doubles as the max tether distance
    RING_THICKNESS = 2
    EASE = 0.22            # 0-1: how quickly the ring catches up each frame (lower = more delay)
    COLOR = "#1e3a8a"       # deep blue
    KEY_COLOR = "#010203"  # a color unlikely to appear naturally, used as the "transparent" key

    def __init__(self, root):
        self.root = root
        self.size = self.RING_RADIUS * 2 + 6

        self.mouse_x = root.winfo_pointerx()
        self.mouse_y = root.winfo_pointery()
        self.ring_x, self.ring_y = float(self.mouse_x), float(self.mouse_y)

        root.config(cursor="none")  # hide the real OS cursor over this window

        self.dot_win = self._make_overlay_window()
        dot_canvas = self._make_canvas(self.dot_win)
        c = self.size / 2
        dot_canvas.create_oval(c - self.DOT_RADIUS, c - self.DOT_RADIUS,
                                c + self.DOT_RADIUS, c + self.DOT_RADIUS,
                                fill=self.COLOR, outline=self.COLOR)

        self.ring_win = self._make_overlay_window()
        ring_canvas = self._make_canvas(self.ring_win)
        ring_canvas.create_oval(3, 3, self.size - 3, self.size - 3,
                                 outline=self.COLOR, width=self.RING_THICKNESS)

        self._animate()

    def _make_overlay_window(self):
        win = tk.Toplevel(self.root)
        win.overrideredirect(True)     # no title bar/border
        win.attributes("-topmost", True)
        win.attributes("-transparentcolor", self.KEY_COLOR)  # Windows-only: makes KEY_COLOR see-through
        win.geometry(f"{self.size}x{self.size}")
        return win

    def _make_canvas(self, win):
        canvas = tk.Canvas(win, width=self.size, height=self.size,
                            bg=self.KEY_COLOR, highlightthickness=0)
        canvas.pack()
        return canvas

    def _animate(self):
        self.mouse_x = self.root.winfo_pointerx()
        self.mouse_y = self.root.winfo_pointery()

        # The dot always snaps exactly to the real mouse position - no delay.
        half = self.size // 2
        self.dot_win.geometry(f"+{self.mouse_x - half}+{self.mouse_y - half}")

        # The ring eases toward the mouse position with a lag.
        self.ring_x += (self.mouse_x - self.ring_x) * self.EASE
        self.ring_y += (self.mouse_y - self.ring_y) * self.EASE

        # Tether: never let the ring drift more than RING_RADIUS pixels from
        # the dot's (the mouse's) position - this is what guarantees the ring
        # always settles back centered on the dot once movement stops.
        dx = self.ring_x - self.mouse_x
        dy = self.ring_y - self.mouse_y
        dist = math.hypot(dx, dy)
        if dist > self.RING_RADIUS:
            scale = self.RING_RADIUS / dist
            self.ring_x = self.mouse_x + dx * scale
            self.ring_y = self.mouse_y + dy * scale

        self.ring_win.geometry(f"+{int(self.ring_x) - half}+{int(self.ring_y) - half}")

        self.root.after(16, self._animate)  # ~60fps


def clear_window(root):
    """Destroys every widget currently in the window, so switching between
    Login <-> Main App <-> Login again never leaves old widgets behind."""
    for widget in root.winfo_children():
        widget.destroy()


class LoginWindow:
    def __init__(self, root, on_success):
        self.root = root
        self.on_success = on_success
        clear_window(root)
        self.root.title("DBMS Project - Login")
        self.root.geometry("340x260")
        self.toast = ToastManager(root)

        tk.Label(root, text="Login", font=("Arial", 16, "bold")).pack(pady=(20, 10))

        tk.Label(root, text="Username:").pack(anchor="w", padx=40)
        self.username_entry = tk.Entry(root, width=30)
        self.username_entry.pack(padx=40)

        tk.Label(root, text="Password:").pack(anchor="w", padx=40, pady=(10, 0))
        self.password_entry = tk.Entry(root, width=30, show="*")
        self.password_entry.pack(padx=40)

        tk.Button(root, text="Login", bg="#4CAF50", fg="white", command=self.handle_login).pack(pady=(15, 5))
        tk.Button(root, text="Register New Account", command=self.handle_register).pack()

        forgot_link = tk.Label(root, text="Forgot Password?", fg="#2563eb", cursor="hand2")
        forgot_link.pack(pady=(10, 0))
        forgot_link.bind("<Button-1>", lambda e: self.open_forgot_password_dialog())

    def open_forgot_password_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Reset Password")
        dialog.geometry("300x220")
        dialog.transient(self.root)
        dialog.grab_set()  # modal - must resolve this dialog before returning to login

        tk.Label(dialog, text="Reset Password", font=("Arial", 13, "bold")).pack(pady=(15, 10))

        tk.Label(dialog, text="Username:").pack(anchor="w", padx=30)
        username_entry = tk.Entry(dialog, width=28)
        username_entry.pack(padx=30)
        username_entry.insert(0, self.username_entry.get().strip())  # prefill if they already typed one

        tk.Label(dialog, text="New Password:").pack(anchor="w", padx=30, pady=(10, 0))
        new_password_entry = tk.Entry(dialog, width=28, show="*")
        new_password_entry.pack(padx=30)

        dialog_toast = ToastManager(dialog)

        def submit():
            username = username_entry.get().strip()
            new_password = new_password_entry.get()
            if not username or not new_password:
                dialog_toast.show("Enter username and new password.", False)
                return
            success, message = change_password(username, new_password)
            if success:
                self.toast.show(message, True)
                dialog.destroy()
            else:
                dialog_toast.show(message, False)

        tk.Button(dialog, text="Reset Password", bg="#4CAF50", fg="white", command=submit).pack(pady=15)

    def handle_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not username or not password:
            self.toast.show("Enter username and password.", False)
            return
        success, message = verify_login(username, password)
        if success:
            clear_window(self.root)  # remove the login screen before building the main app
            self.on_success(username)
        else:
            self.toast.show(friendly_error(message), False)

    def handle_register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not username or not password:
            self.toast.show("Enter a username and password to register.", False)
            return
        success, message = register_user(username, password)
        self.toast.show(message, success)


BG_MAIN = "#f8fafc"
TEXT_MAIN = "#1e293b"

CATEGORY_COLORS = {
    "Table": {"bg": "#dbeafe", "fg": "#1e40af"},
    "Insert Data": {"bg": "#fef2f2", "fg": "#f87171"},
    "Account": {"bg": "#ecfdf5", "fg": "#059669"},
    "Behind the Scenes": {"bg": "#eff6ff", "fg": "#2563eb"},
    "Timetable": {"bg": "#fff7ed", "fg": "#c2410c"},
}

# Which category each tab belongs to, so the main content area can be tinted
# to match whichever category you're currently working in.
TAB_CATEGORY = {
    "my_tables": "Table", "create": "Table", "update_table": "Table",
    "rename_table": "Table", "drop_table": "Table",
    "insert": "Insert Data", "view": "Insert Data",
    "update_row": "Insert Data", "delete_row": "Insert Data",
    "account": "Account",
    "timetable": "Timetable",
}


class DBMSApp:
    def __init__(self, root, username):
        self.root = root
        self.username = username
        self.prefix = re.sub(r'[^A-Za-z0-9_]', '', username).upper() + "_"

        self.root.title("DBMS Project - Python Desktop GUI")
        self.root.geometry("1050x680")

        topbar = tk.Frame(root, bg="#ffffff", height=45)
        topbar.pack(fill="x", side="top")
        self.hamburger_btn = tk.Button(topbar, text="\u2630", command=self.toggle_sidebar, relief="flat")
        self.hamburger_btn.pack(side="left", padx=10, pady=8)
        tk.Label(topbar, text="DBMS Web Interface", font=("Arial", 12, "bold"), bg="#ffffff").pack(side="left", padx=5)
        tk.Label(topbar, text=f"Logged in as {username}", bg="#ffffff", fg="#64748b").pack(side="right", padx=15)

        body = tk.Frame(root, bg=BG_MAIN)
        body.pack(fill="both", expand=True)

        self.sidebar = tk.Frame(body, width=230, bg="#ffffff")
        self.sidebar_visible = True
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Query log panel: a DOCKED side panel (not a full-screen exclusive tab)
        # so the normal content area stays usable to its right at the same time.
        self.query_log_panel = tk.Frame(body, width=340, bg="#ffffff")
        self.query_log_panel_visible = False
        self.query_log_panel.pack_propagate(False)
        # not packed yet - stays hidden until toggled

        self.content_area = tk.Frame(body, bg=BG_MAIN)
        self.content_area.pack(side="left", fill="both", expand=True)

        self.frames = {}
        self.toast = ToastManager(self.root)
        self.all_table_dropdowns = []
        self.insert_col_types = {}
        self.update_col_types = {}
        self.delete_col_types = {}

        self.build_query_log_panel()
        self.build_sidebar()
        self.build_all_tabs()
        self.show_tab("my_tables")
        self.start_query_log_auto_refresh()

    def toggle_sidebar(self):
        if self.sidebar_visible:
            self.sidebar.pack_forget()
        else:
            self.sidebar.pack(side="left", fill="y", before=self.content_area)
        self.sidebar_visible = not self.sidebar_visible

    @staticmethod
    def _lighten(hex_color, factor=0.6):
        """Blend a hex color toward white by `factor` (0 = no change, 1 = white)."""
        hex_color = hex_color.lstrip('#')
        r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
        r = int(r + (255 - r) * factor)
        g = int(g + (255 - g) * factor)
        b = int(b + (255 - b) * factor)
        return f"#{r:02x}{g:02x}{b:02x}"

    def build_sidebar(self):
        categories = {
            "Table": [("My Tables", "my_tables"), ("Create Table", "create"), ("Update Table", "update_table"),
                      ("Rename Table", "rename_table"), ("Delete Table", "drop_table")],
            "Insert Data": [("Insert Row", "insert"), ("View Data", "view"),
                             ("Update Row", "update_row"), ("Delete Row", "delete_row")],
            "Account": [("Account Settings", "account")],
            "Behind the Scenes": [("Query Log", "query_log")],
            "Timetable": [("Busy/Free Timetable", "timetable")],
        }

        # Using grid() with a running row counter (instead of pack()) so that
        # collapsing/expanding a category with grid_remove()/grid() ALWAYS
        # restores it to its original row - pack_forget()/pack() instead moves
        # a re-shown widget to the end of the packing order, which is exactly
        # what caused everything to scramble before.
        row = 0
        for cat_name, items in categories.items():
            colors = CATEGORY_COLORS[cat_name]
            item_bg = self._lighten(colors["bg"], 0.35)  # slightly stronger tint than the title itself

            title = tk.Label(self.sidebar, text=cat_name.upper(), bg=colors["bg"], fg=colors["fg"],
                              font=("Arial", 9, "bold"), anchor="w", padx=15, pady=8, cursor="hand2")
            title.grid(row=row, column=0, sticky="ew", padx=8, pady=(8, 0))
            self.sidebar.grid_rowconfigure(row, weight=0)
            row += 1

            items_frame = tk.Frame(self.sidebar, bg="#ffffff")
            items_frame.grid(row=row, column=0, sticky="ew")
            self.sidebar.grid_columnconfigure(0, weight=1)

            for label, tab_key in items:
                if tab_key == "query_log":
                    btn = tk.Button(items_frame, text=label, anchor="w", relief="flat", bg=item_bg, fg=colors["fg"],
                                     activebackground=colors["bg"], padx=25, pady=7, bd=0,
                                     command=self.toggle_query_log_panel)
                else:
                    btn = tk.Button(items_frame, text=label, anchor="w", relief="flat", bg=item_bg, fg=colors["fg"],
                                     activebackground=colors["bg"], padx=25, pady=7, bd=0,
                                     command=lambda k=tab_key: self.show_tab(k))
                btn.pack(fill="x", padx=8, pady=1)
                # Simple hover effect for a less plain look
                btn.bind("<Enter>", lambda e, b=btn, c=colors["bg"]: b.config(bg=c))
                btn.bind("<Leave>", lambda e, b=btn, c=item_bg: b.config(bg=c))

            title.bind("<Button-1>", lambda e, f=items_frame: self.toggle_category(f))
            row += 1

    def toggle_category(self, items_frame):
        if items_frame.winfo_viewable():
            items_frame.grid_remove()   # preserves its row/column slot
        else:
            items_frame.grid()          # restores it to that exact slot

    def toggle_query_log_panel(self):
        """Opens/closes the query log as a DOCKED side panel next to the
        sidebar - unlike a normal tab, the main content area stays fully
        usable to its right at the same time, so you can keep working on
        Create Table / Insert Row / etc. while watching the log."""
        if self.query_log_panel_visible:
            self.query_log_panel.pack_forget()
        else:
            self.query_log_panel.pack(side="left", fill="y", before=self.content_area)
            self.refresh_query_log()
        self.query_log_panel_visible = not self.query_log_panel_visible

    def start_query_log_auto_refresh(self):
        """Keeps the query log panel live without needing a manual Refresh
        click - checks every 2 seconds and only actually refreshes (and only
        does any work at all) while the panel is currently open."""
        if self.query_log_panel_visible:
            self.refresh_query_log()
        self.root.after(2000, self.start_query_log_auto_refresh)

    def show_tab(self, tab_key):
        for frame in self.frames.values():
            frame.pack_forget()
        self.frames[tab_key].pack(fill="both", expand=True, padx=25, pady=20)
        self.refresh_table_dropdowns()
        if tab_key == "my_tables":
            self.refresh_my_tables_list()

        category = TAB_CATEGORY.get(tab_key)
        if category:
            tint = CATEGORY_COLORS[category]["bg"]
            self.content_area.configure(bg=tint)
            self.frames[tab_key].configure(bg=tint)
            self._recolor_widget_tree(self.frames[tab_key], tint)

    def _recolor_widget_tree(self, widget, color):
        """Recursively tints every plain Frame/Label/LabelFrame/Canvas found
        inside `widget` with `color` - skips Entry/Text/Treeview/Combobox/
        Scrollbar so input fields and data tables stay white for contrast,
        and skips any widget (and its children) flagged with
        `protected_color = True`, e.g. the red Delete Account warning box."""
        colorable_classes = ("Frame", "Label", "Labelframe", "Canvas")
        for child in widget.winfo_children():
            if getattr(child, "protected_color", False):
                continue
            if child.winfo_class() in colorable_classes:
                try:
                    child.configure(bg=color)
                except tk.TclError:
                    pass  # some widgets accept 'bg' under a different option name
            self._recolor_widget_tree(child, color)

    def make_scrollable(self, container):
        """Wraps `container` with a Canvas + vertical Scrollbar and returns an
        inner Frame to build widgets into - if the content ends up taller
        than the window, a scrollbar appears automatically instead of the
        content being cut off. Also supports mouse-wheel scrolling while
        hovering over that tab."""
        canvas = tk.Canvas(container, bg=BG_MAIN, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=BG_MAIN)

        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind("<MouseWheel>", _on_mousewheel)
        inner.bind("<MouseWheel>", _on_mousewheel)

        return inner

    def build_all_tabs(self):
        for key in ["my_tables", "create", "update_table", "rename_table", "drop_table",
                    "insert", "view", "update_row", "delete_row", "account", "timetable"]:
            self.frames[key] = tk.Frame(self.content_area, bg=BG_MAIN)

        self.build_my_tables_tab(self.frames["my_tables"])
        self.build_create_tab(self.make_scrollable(self.frames["create"]))
        self.build_update_table_tab(self.make_scrollable(self.frames["update_table"]))
        self.build_rename_table_tab(self.make_scrollable(self.frames["rename_table"]))
        self.build_drop_table_tab(self.make_scrollable(self.frames["drop_table"]))
        self.build_insert_tab(self.make_scrollable(self.frames["insert"]))
        self.build_view_tab(self.frames["view"])
        self.build_update_row_tab(self.make_scrollable(self.frames["update_row"]))
        self.build_delete_row_tab(self.make_scrollable(self.frames["delete_row"]))
        self.build_account_tab(self.make_scrollable(self.frames["account"]))
        self.build_timetable_tab(self.make_scrollable(self.frames["timetable"]))

    def build_my_tables_tab(self, frame):
        tk.Label(frame, text="My Tables", font=("Arial", 14, "bold"), bg=BG_MAIN).pack(anchor="w")
        tk.Label(frame, text="Every table that belongs to your account (only your own - other users' tables never appear here).",
                 fg="#666", bg=BG_MAIN, wraplength=500, justify="left").pack(anchor="w", pady=(5, 10))

        tk.Button(frame, text="Refresh", command=self.refresh_my_tables_list).pack(anchor="w", pady=(0, 10))

        columns = ("table_name",)
        tree_container = tk.Frame(frame, bg=BG_MAIN)
        tree_container.pack(fill="both", expand=True)

        self.my_tables_tree = ttk.Treeview(tree_container, columns=columns, show="headings")
        self.my_tables_tree.heading("table_name", text="Table Name")
        self.my_tables_tree.column("table_name", width=300)

        v_scroll = ttk.Scrollbar(tree_container, orient="vertical", command=self.my_tables_tree.yview)
        h_scroll = ttk.Scrollbar(tree_container, orient="horizontal", command=self.my_tables_tree.xview)
        self.my_tables_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.my_tables_tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)

    def refresh_my_tables_list(self):
        self.my_tables_tree.delete(*self.my_tables_tree.get_children())
        for table_name in get_table_names(self.prefix):
            self.my_tables_tree.insert("", tk.END, values=(table_name,))

    # ================= TIMETABLE (busy/free slot grid) =================
    TIMETABLE_START_HOUR = 8   # 8 AM
    TIMETABLE_END_HOUR = 20    # 8 PM (last slot shown is 19:00-20:00)

    def build_timetable_tab(self, frame):
        tk.Label(frame, text="Busy / Free Timetable", font=("Arial", 14, "bold"), bg=BG_MAIN).pack(anchor="w")
        tk.Label(frame, text="Works with any of your tables that has a start-time column. Shows hourly "
                             "slots from 8 AM to 8 PM as Busy or Free.",
                 fg="#666", bg=BG_MAIN, wraplength=550, justify="left").pack(anchor="w", pady=(5, 15))

        tk.Label(frame, text="Select Table:", bg=BG_MAIN).pack(anchor="w")
        self.timetable_table_var = tk.StringVar()
        self.timetable_table_dropdown = ttk.Combobox(frame, textvariable=self.timetable_table_var, state="readonly", width=30)
        self.timetable_table_dropdown.pack(anchor="w")
        self.timetable_table_dropdown.bind("<<ComboboxSelected>>", self.on_timetable_table_selected)
        self.all_table_dropdowns.append(self.timetable_table_dropdown)

        tk.Label(frame, text="Start Time Column:", bg=BG_MAIN).pack(anchor="w", pady=(10, 0))
        self.timetable_start_col_var = tk.StringVar()
        self.timetable_start_col_dropdown = ttk.Combobox(frame, textvariable=self.timetable_start_col_var, state="readonly", width=30)
        self.timetable_start_col_dropdown.pack(anchor="w")

        # Mode: some tables (like workout_sessions) don't have a separate end
        # time column - only a start time plus a duration in minutes. This
        # toggle lets the second dropdown mean either one.
        tk.Label(frame, text="How is the end of the booking determined?", bg=BG_MAIN).pack(anchor="w", pady=(10, 0))
        self.timetable_mode_var = tk.StringVar(value="end_col")
        mode_row = tk.Frame(frame, bg=BG_MAIN)
        mode_row.pack(anchor="w")
        tk.Radiobutton(mode_row, text="I have an End Time column", variable=self.timetable_mode_var,
                        value="end_col", bg=BG_MAIN, command=self.on_timetable_mode_changed).pack(anchor="w")
        tk.Radiobutton(mode_row, text="I only have a Duration (minutes) column", variable=self.timetable_mode_var,
                        value="duration", bg=BG_MAIN, command=self.on_timetable_mode_changed).pack(anchor="w")

        self.timetable_end_col_label = tk.Label(frame, text="End Time Column:", bg=BG_MAIN)
        self.timetable_end_col_label.pack(anchor="w", pady=(10, 0))
        self.timetable_end_col_var = tk.StringVar()
        self.timetable_end_col_dropdown = ttk.Combobox(frame, textvariable=self.timetable_end_col_var, state="readonly", width=30)
        self.timetable_end_col_dropdown.pack(anchor="w")

        tk.Label(frame, text="Date Range (YYYY-MM-DD):", bg=BG_MAIN).pack(anchor="w", pady=(10, 0))
        date_row = tk.Frame(frame, bg=BG_MAIN)
        date_row.pack(anchor="w")
        self.timetable_date_from_entry = tk.Entry(date_row, width=14)
        self.timetable_date_from_entry.pack(side="left")
        tk.Label(date_row, text=" to ", bg=BG_MAIN).pack(side="left")
        self.timetable_date_to_entry = tk.Entry(date_row, width=14)
        self.timetable_date_to_entry.pack(side="left")

        today_str = datetime.now().strftime("%Y-%m-%d")
        self.timetable_date_from_entry.insert(0, today_str)
        self.timetable_date_to_entry.insert(0, today_str)

        tk.Button(frame, text="Generate Timetable", command=self.on_generate_timetable,
                  bg="#c2410c", fg="white").pack(anchor="w", pady=15)

        # Legend
        legend = tk.Frame(frame, bg=BG_MAIN)
        legend.protected_color = True  # keep the red/green swatches exactly as set
        legend.pack(anchor="w", pady=(0, 10))
        tk.Label(legend, text="  ", bg="#fee2e2", width=2).pack(side="left")
        tk.Label(legend, text="Busy   ", bg=BG_MAIN).pack(side="left")
        tk.Label(legend, text="  ", bg="#dcfce7", width=2).pack(side="left")
        tk.Label(legend, text="Free", bg=BG_MAIN).pack(side="left")

        self.timetable_results_container = tk.Frame(frame, bg=BG_MAIN)
        self.timetable_results_container.protected_color = True  # keep Busy/Free cell colors intact
        self.timetable_results_container.pack(anchor="w", fill="both", expand=True)

    """def on_timetable_table_selected(self, event=None):
        table = self.timetable_table_var.get()
        if not table:
            return
        columns = get_column_names(self.prefix, table)
        self.timetable_start_col_dropdown["values"] = columns
        self.timetable_end_col_dropdown["values"] = columns"""

    
    def on_timetable_table_selected(self, event=None):
        table = self.timetable_table_var.get()

        if not table:
            return

        columns = get_column_names(self.prefix, table)

        self.timetable_start_col_dropdown["values"] = columns
        self.timetable_end_col_dropdown["values"] = columns

        # Automatically choose a suitable start-time column.
        start_candidates = [
            "SESSION_DATE",
            "START_TIME",
            "START_DATE",
            "BOOKING_DATE",
            "BOOKING_TIME",
        ]

        start_col = next(
            (c for candidate in start_candidates
            for c in columns if c.upper() == candidate),
            None
        )

        if start_col is None:
            self.timetable_start_col_var.set("")
            self.timetable_end_col_var.set("")
            self.toast.show(
                "Select a valid start-time column manually.",
                False
            )
            return

        self.timetable_start_col_var.set(start_col)

        # Prefer a duration column when one exists.
        duration_col = next(
            (c for c in columns
            if "DURATION" in c.upper()
            and ("MINUTE" in c.upper() or "MIN" in c.upper())),
            None
        )

        end_candidates = [
            "END_TIME",
            "END_DATE",
            "END_DATETIME",
            "END_TIMESTAMP",
        ]

        end_col = next(
            (c for candidate in end_candidates
            for c in columns if c.upper() == candidate),
            None
        )

        if duration_col:
            self.timetable_mode_var.set("duration")
            self.on_timetable_mode_changed()
            self.timetable_end_col_var.set(duration_col)

        elif end_col:
            self.timetable_mode_var.set("end_col")
            self.on_timetable_mode_changed()
            self.timetable_end_col_var.set(end_col)

        else:
            self.timetable_end_col_var.set("")
            self.toast.show(
                "No end-time or duration column found.",
                False
            )


    def on_timetable_mode_changed(self):
        if self.timetable_mode_var.get() == "duration":
            self.timetable_end_col_label.config(text="Duration (minutes) Column:")
        else:
            self.timetable_end_col_label.config(text="End Time Column:")

    def on_generate_timetable(self):
        table = self.timetable_table_var.get()
        start_col = self.timetable_start_col_var.get()
        end_col = self.timetable_end_col_var.get()
        date_from = self.timetable_date_from_entry.get().strip()
        date_to = self.timetable_date_to_entry.get().strip()

        if not table:
            self.toast.show("Select a table.", False)
            return
        if not start_col or not end_col:
            self.toast.show("Select both a start time and end time column.", False)
            return

        try:
            d_from = datetime.strptime(date_from, "%Y-%m-%d").date()
            d_to = datetime.strptime(date_to, "%Y-%m-%d").date()
        except ValueError:
            self.toast.show("Dates must be in YYYY-MM-DD format.", False)
            return
        if d_to < d_from:
            self.toast.show("End date must be on or after the start date.", False)
            return
        if (d_to - d_from).days > 31:
            self.toast.show("Please pick a range of 31 days or less.", False)
            return

        use_duration = self.timetable_mode_var.get() == "duration"
        success, result = get_bookings_in_range(self.prefix, table, start_col, end_col, date_from, date_to, use_duration)
        if not success:
            self.toast.show(friendly_error(result), False)
            return

        bookings = result  # list of (start_datetime, end_datetime)
        self._render_timetable_grid(d_from, d_to, bookings)
        self.toast.show(f"Timetable generated for {len(bookings)} booking(s).", True)

    def _render_timetable_grid(self, d_from, d_to, bookings):
        for widget in self.timetable_results_container.winfo_children():
            widget.destroy()

        hours = list(range(self.TIMETABLE_START_HOUR, self.TIMETABLE_END_HOUR))
        num_days = (d_to - d_from).days + 1

        # Header row: blank corner + one header per hour
        tk.Label(self.timetable_results_container, text="Date", bg="#e2e8f0", width=12,
                 relief="solid", borderwidth=1, font=("Arial", 8, "bold")).grid(row=0, column=0)
        for col, hour in enumerate(hours, start=1):
            tk.Label(self.timetable_results_container, text=f"{hour:02d}:00", bg="#e2e8f0", width=6,
                     relief="solid", borderwidth=1, font=("Arial", 8, "bold")).grid(row=0, column=col)

        for row_index in range(num_days):
            day = d_from + timedelta(days=row_index)
            tk.Label(self.timetable_results_container, text=day.strftime("%Y-%m-%d"), bg="#e2e8f0", width=12,
                     relief="solid", borderwidth=1, font=("Arial", 8, "bold")).grid(row=row_index + 1, column=0)

            for col, hour in enumerate(hours, start=1):
                slot_start = datetime(day.year, day.month, day.day, hour, 0)
                slot_end = slot_start + timedelta(hours=1)

                is_busy = any(
                    b_start is not None and b_end is not None and b_start < slot_end and b_end > slot_start
                    for b_start, b_end in bookings
                )

                bg = "#fee2e2" if is_busy else "#dcfce7"
                tk.Label(self.timetable_results_container, text="", bg=bg, width=6,
                         relief="solid", borderwidth=1).grid(row=row_index + 1, column=col)

    def build_create_tab(self, frame):
        tk.Label(frame, text="Create a New Table", font=("Arial", 14, "bold")).pack(anchor="w")
        tk.Label(frame, text="Table Name:").pack(anchor="w", pady=(15, 0))
        self.table_name_entry = tk.Entry(frame, width=40)
        self.table_name_entry.pack(anchor="w")

        tk.Label(frame, text="Columns:").pack(anchor="w", pady=(15, 0))
        self.create_columns_frame = tk.Frame(frame)
        self.create_columns_frame.pack(anchor="w", fill="x")
        self.create_column_rows = []

        tk.Button(frame, text="+ Add Column", command=self.add_create_column_row).pack(anchor="w", pady=5)
        tk.Button(frame, text="Create Table", command=self.on_create_table, bg="#4CAF50", fg="white").pack(anchor="w", pady=10)

        self.add_create_column_row()

    def add_create_column_row(self):
        row_frame = tk.Frame(self.create_columns_frame)
        row_frame.pack(fill="x", pady=2)

        name_entry = tk.Entry(row_frame, width=18)
        name_entry.pack(side="left", padx=2)

        type_combo = ttk.Combobox(row_frame, values=COLUMN_TYPES, width=15, state="readonly")
        type_combo.current(0)
        type_combo.pack(side="left", padx=2)

        constraint_combo = ttk.Combobox(row_frame, values=COLUMN_CONSTRAINTS, width=12, state="readonly")
        constraint_combo.current(0)
        constraint_combo.pack(side="left", padx=2)

        tk.Button(row_frame, text="Remove", command=lambda: self.remove_create_column_row(row_frame)).pack(side="left", padx=2)

        self.create_column_rows.append({"name": name_entry, "type": type_combo, "constraint": constraint_combo, "row_frame": row_frame})

    def remove_create_column_row(self, row_frame):
        if len(self.create_column_rows) <= 1:
            self.toast.show("At least one column is required.", False)
            return
        self.create_column_rows = [r for r in self.create_column_rows if r["row_frame"] != row_frame]
        row_frame.destroy()

    def on_create_table(self):
        table_name = self.table_name_entry.get().strip()
        if not table_name:
            self.toast.show("Enter a table name.", False)
            return

        columns = []
        for row in self.create_column_rows:
            name = row["name"].get().strip()
            if name:
                columns.append((name, row["type"].get(), row["constraint"].get()))

        if not columns:
            self.toast.show("Add at least one column with a name.", False)
            return

        success, message = create_table(self.prefix, table_name, columns)
        if success:
            self.toast.show(message, True)
            self.table_name_entry.delete(0, tk.END)
            for row in self.create_column_rows[1:]:
                row["row_frame"].destroy()
            self.create_column_rows = self.create_column_rows[:1]
            self.create_column_rows[0]["name"].delete(0, tk.END)
            self.refresh_table_dropdowns()
        else:
            self.toast.show(friendly_error(message), False)

    def build_update_table_tab(self, frame):
        tk.Label(frame, text="Update Table", font=("Arial", 14, "bold")).pack(anchor="w")

        add_section = tk.LabelFrame(frame, text="Add Column", padx=10, pady=10)
        add_section.pack(fill="x", pady=10)

        tk.Label(add_section, text="Select Table:").grid(row=0, column=0, sticky="w")
        self.add_col_table_var = tk.StringVar()
        self.add_col_table_dropdown = ttk.Combobox(add_section, textvariable=self.add_col_table_var, state="readonly", width=25)
        self.add_col_table_dropdown.grid(row=0, column=1, padx=5)
        self.all_table_dropdowns.append(self.add_col_table_dropdown)

        tk.Label(add_section, text="New Column Name:").grid(row=1, column=0, sticky="w", pady=5)
        self.add_col_name_entry = tk.Entry(add_section, width=27)
        self.add_col_name_entry.grid(row=1, column=1, padx=5)

        tk.Label(add_section, text="Type:").grid(row=2, column=0, sticky="w")
        self.add_col_type_combo = ttk.Combobox(add_section, values=COLUMN_TYPES, state="readonly", width=25)
        self.add_col_type_combo.current(0)
        self.add_col_type_combo.grid(row=2, column=1, padx=5)

        tk.Button(add_section, text="Add Column", command=self.on_add_column, bg="#4CAF50", fg="white").grid(row=3, column=1, sticky="w", pady=8)

        rename_section = tk.LabelFrame(frame, text="Rename Column", padx=10, pady=10)
        rename_section.pack(fill="x", pady=10)

        tk.Label(rename_section, text="Select Table:").grid(row=0, column=0, sticky="w")
        self.rename_col_table_var = tk.StringVar()
        self.rename_col_table_dropdown = ttk.Combobox(rename_section, textvariable=self.rename_col_table_var, state="readonly", width=25)
        self.rename_col_table_dropdown.grid(row=0, column=1, padx=5)
        self.rename_col_table_dropdown.bind("<<ComboboxSelected>>", self.on_rename_col_table_selected)
        self.all_table_dropdowns.append(self.rename_col_table_dropdown)

        tk.Label(rename_section, text="Select Column:").grid(row=1, column=0, sticky="w", pady=5)
        self.rename_col_old_var = tk.StringVar()
        self.rename_col_old_dropdown = ttk.Combobox(rename_section, textvariable=self.rename_col_old_var, state="readonly", width=25)
        self.rename_col_old_dropdown.grid(row=1, column=1, padx=5)

        tk.Label(rename_section, text="New Column Name:").grid(row=2, column=0, sticky="w")
        self.rename_col_new_entry = tk.Entry(rename_section, width=27)
        self.rename_col_new_entry.grid(row=2, column=1, padx=5)

        tk.Button(rename_section, text="Rename Column", command=self.on_rename_column, bg="#4CAF50", fg="white").grid(row=3, column=1, sticky="w", pady=8)

    def on_rename_col_table_selected(self, event=None):
        table = self.rename_col_table_var.get()
        if table:
            self.rename_col_old_dropdown["values"] = get_column_names(self.prefix, table)

    def on_add_column(self):
        table = self.add_col_table_var.get()
        col_name = self.add_col_name_entry.get().strip()
        if not table:
            self.toast.show("Select a table.", False)
            return
        if not col_name:
            self.toast.show("Enter a column name.", False)
            return
        success, message = add_column(self.prefix, table, col_name, self.add_col_type_combo.get())
        if success:
            self.toast.show(message, True)
            self.add_col_name_entry.delete(0, tk.END)
        else:
            self.toast.show(friendly_error(message), False)

    def on_rename_column(self):
        table = self.rename_col_table_var.get()
        old_col = self.rename_col_old_var.get()
        new_col = self.rename_col_new_entry.get().strip()
        if not table or not old_col:
            self.toast.show("Select a table and column.", False)
            return
        if not new_col:
            self.toast.show("Enter a new column name.", False)
            return
        success, message = rename_column(self.prefix, table, old_col, new_col)
        if success:
            self.toast.show(message, True)
            self.rename_col_new_entry.delete(0, tk.END)
            self.on_rename_col_table_selected()
        else:
            self.toast.show(friendly_error(message), False)

    def build_rename_table_tab(self, frame):
        tk.Label(frame, text="Rename Table", font=("Arial", 14, "bold")).pack(anchor="w")

        tk.Label(frame, text="Select Table:").pack(anchor="w", pady=(15, 0))
        self.rename_table_var = tk.StringVar()
        self.rename_table_dropdown = ttk.Combobox(frame, textvariable=self.rename_table_var, state="readonly", width=30)
        self.rename_table_dropdown.pack(anchor="w")
        self.all_table_dropdowns.append(self.rename_table_dropdown)

        tk.Label(frame, text="New Table Name:").pack(anchor="w", pady=(10, 0))
        self.rename_table_new_entry = tk.Entry(frame, width=33)
        self.rename_table_new_entry.pack(anchor="w")

        tk.Button(frame, text="Rename", command=self.on_rename_table, bg="#4CAF50", fg="white").pack(anchor="w", pady=10)

    def on_rename_table(self):
        old_name = self.rename_table_var.get()
        new_name = self.rename_table_new_entry.get().strip()
        if not old_name:
            self.toast.show("Select a table.", False)
            return
        if not new_name:
            self.toast.show("Enter a new table name.", False)
            return
        success, message = rename_table(self.prefix, old_name, new_name)
        if success:
            self.toast.show(message, True)
            self.rename_table_new_entry.delete(0, tk.END)
            self.refresh_table_dropdowns()
        else:
            self.toast.show(friendly_error(message), False)

    def build_drop_table_tab(self, frame):
        tk.Label(frame, text="Delete Table", font=("Arial", 14, "bold")).pack(anchor="w")
        tk.Label(frame, text="Warning: this permanently deletes the entire table and all its data.", fg="red").pack(anchor="w", pady=(10, 0))

        tk.Label(frame, text="Select Table:").pack(anchor="w", pady=(10, 0))
        self.drop_table_var = tk.StringVar()
        self.drop_table_dropdown = ttk.Combobox(frame, textvariable=self.drop_table_var, state="readonly", width=30)
        self.drop_table_dropdown.pack(anchor="w")
        self.all_table_dropdowns.append(self.drop_table_dropdown)

        tk.Button(frame, text="Drop Table", command=self.on_drop_table, bg="#d9534f", fg="white").pack(anchor="w", pady=10)

    def on_drop_table(self):
        table = self.drop_table_var.get()
        if not table:
            self.toast.show("Select a table.", False)
            return
        if not messagebox.askyesno("Confirm", f"Permanently drop table '{table}'? This cannot be undone."):
            return
        success, message = drop_table(self.prefix, table)
        if success:
            self.toast.show(message, True)
            self.drop_table_var.set("")
            self.refresh_table_dropdowns()
        else:
            self.toast.show(friendly_error(message), False)

    def build_insert_tab(self, frame):
        tk.Label(frame, text="Insert Data", font=("Arial", 14, "bold")).pack(anchor="w")

        tk.Label(frame, text="Select Table:").pack(anchor="w", pady=(15, 0))
        self.insert_table_var = tk.StringVar()
        self.insert_table_dropdown = ttk.Combobox(frame, textvariable=self.insert_table_var, state="readonly", width=30)
        self.insert_table_dropdown.pack(anchor="w")
        self.insert_table_dropdown.bind("<<ComboboxSelected>>", self.on_insert_table_selected)
        self.all_table_dropdowns.append(self.insert_table_dropdown)

        self.insert_fields_frame = tk.Frame(frame)
        self.insert_fields_frame.pack(anchor="w", pady=10, fill="x")
        self.insert_entries = {}

        tk.Button(frame, text="Insert Row", command=self.on_insert_row, bg="#4CAF50", fg="white").pack(anchor="w")

    def on_insert_table_selected(self, event=None):
        for widget in self.insert_fields_frame.winfo_children():
            widget.destroy()
        self.insert_entries = {}
        table = self.insert_table_var.get()
        if not table:
            return
        columns = get_table_columns(self.prefix, table)
        self.insert_col_types = {c["name"]: c["type"] for c in columns}
        for col in columns:
            row = tk.Frame(self.insert_fields_frame)
            row.pack(fill="x", pady=2)
            label_text = col["name"]
            if col["type"] in ("DATE", "TIMESTAMP", "TIMESTAMP(6)"):
                label_text += " (YYYY-MM-DD)"
            tk.Label(row, text=label_text, width=28, anchor="w").pack(side="left")
            entry = tk.Entry(row, width=30)
            entry.pack(side="left")
            self.insert_entries[col["name"]] = entry

    def on_insert_row(self):
        table = self.insert_table_var.get()
        if not table:
            self.toast.show("Select a table first.", False)
            return
        columns = list(self.insert_entries.keys())
        values = [self.insert_entries[col].get().strip() for col in columns]
        success, message = insert_row(self.prefix, table, columns, values, self.insert_col_types)
        if success:
            self.toast.show(message, True)
            for entry in self.insert_entries.values():
                entry.delete(0, tk.END)
        else:
            self.toast.show(friendly_error(message), False)

    def build_view_tab(self, frame):
        tk.Label(frame, text="View Data", font=("Arial", 14, "bold")).pack(anchor="w")

        tk.Label(frame, text="Select Table:").pack(anchor="w", pady=(15, 0))
        self.view_table_var = tk.StringVar()
        self.view_table_dropdown = ttk.Combobox(frame, textvariable=self.view_table_var, state="readonly", width=30)
        self.view_table_dropdown.pack(anchor="w")
        self.all_table_dropdowns.append(self.view_table_dropdown)

        tk.Button(frame, text="Load Data", command=self.on_load_data, bg="#4CAF50", fg="white").pack(anchor="w", pady=10)

        tree_container = tk.Frame(frame, bg=BG_MAIN)
        tree_container.pack(fill="both", expand=True)

        self.data_tree = ttk.Treeview(tree_container)
        v_scroll = ttk.Scrollbar(tree_container, orient="vertical", command=self.data_tree.yview)
        h_scroll = ttk.Scrollbar(tree_container, orient="horizontal", command=self.data_tree.xview)
        self.data_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.data_tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)

    def on_load_data(self):
        table = self.view_table_var.get()
        if not table:
            self.toast.show("Select a table first.", False)
            return
        success, columns_or_error, rows = get_all_rows(self.prefix, table)
        if not success:
            self.toast.show(columns_or_error, False)
            return
        columns = columns_or_error
        self.data_tree.delete(*self.data_tree.get_children())
        self.data_tree["columns"] = columns
        self.data_tree["show"] = "headings"
        for col in columns:
            self.data_tree.heading(col, text=col)
            self.data_tree.column(col, width=100)
        for row in rows:
            self.data_tree.insert("", tk.END, values=row)

    def build_update_row_tab(self, frame):
        tk.Label(frame, text="Update Row", font=("Arial", 14, "bold")).pack(anchor="w")

        tk.Label(frame, text="Select Table:").pack(anchor="w", pady=(15, 0))
        self.update_row_table_var = tk.StringVar()
        self.update_row_table_dropdown = ttk.Combobox(frame, textvariable=self.update_row_table_var, state="readonly", width=30)
        self.update_row_table_dropdown.pack(anchor="w")
        self.update_row_table_dropdown.bind("<<ComboboxSelected>>", self.on_update_row_table_selected)
        self.all_table_dropdowns.append(self.update_row_table_dropdown)

        tk.Label(frame, text="Find Row (match on these):").pack(anchor="w", pady=(10, 0))
        self.update_find_frame = tk.Frame(frame)
        self.update_find_frame.pack(anchor="w", fill="x")

        tk.Label(frame, text="New Values (change to these):").pack(anchor="w", pady=(10, 0))
        self.update_new_frame = tk.Frame(frame)
        self.update_new_frame.pack(anchor="w", fill="x")

        self.update_find_entries = {}
        self.update_new_entries = {}

        tk.Button(frame, text="Update Row", command=self.on_update_row, bg="#4CAF50", fg="white").pack(anchor="w", pady=10)

    def on_update_row_table_selected(self, event=None):
        for widget in self.update_find_frame.winfo_children():
            widget.destroy()
        for widget in self.update_new_frame.winfo_children():
            widget.destroy()
        self.update_find_entries = {}
        self.update_new_entries = {}
        table = self.update_row_table_var.get()
        if not table:
            return
        columns = get_table_columns(self.prefix, table)
        self.update_col_types = {c["name"]: c["type"] for c in columns}
        for col in columns:
            label_text = col["name"]
            if col["type"] in ("DATE", "TIMESTAMP", "TIMESTAMP(6)"):
                label_text += " (YYYY-MM-DD)"

            row1 = tk.Frame(self.update_find_frame)
            row1.pack(fill="x", pady=2)
            tk.Label(row1, text=label_text, width=28, anchor="w").pack(side="left")
            entry1 = tk.Entry(row1, width=30)
            entry1.pack(side="left")
            self.update_find_entries[col["name"]] = entry1

            row2 = tk.Frame(self.update_new_frame)
            row2.pack(fill="x", pady=2)
            tk.Label(row2, text=label_text, width=28, anchor="w").pack(side="left")
            entry2 = tk.Entry(row2, width=30)
            entry2.pack(side="left")
            self.update_new_entries[col["name"]] = entry2

    def on_update_row(self):
        table = self.update_row_table_var.get()
        if not table:
            self.toast.show("Select a table first.", False)
            return
        where_columns, where_values = [], []
        for col, entry in self.update_find_entries.items():
            val = entry.get().strip()
            if val != "":
                where_columns.append(col)
                where_values.append(val)
        set_columns, set_values = [], []
        for col, entry in self.update_new_entries.items():
            val = entry.get().strip()
            if val != "":
                set_columns.append(col)
                set_values.append(val)
        if not where_columns:
            self.toast.show("Fill in at least one 'Find Row' field.", False)
            return
        if not set_columns:
            self.toast.show("Fill in at least one 'New Values' field.", False)
            return
        if not messagebox.askyesno("Confirm", "Update the matching row(s)?"):
            return
        success, message = update_rows(self.prefix, table, set_columns, set_values, where_columns, where_values, self.update_col_types)
        if success:
            self.toast.show(message, True)
            for entry in self.update_find_entries.values():
                entry.delete(0, tk.END)
            for entry in self.update_new_entries.values():
                entry.delete(0, tk.END)
        else:
            self.toast.show(friendly_error(message), False)

    def build_delete_row_tab(self, frame):
        tk.Label(frame, text="Delete Row", font=("Arial", 14, "bold")).pack(anchor="w")

        tk.Label(frame, text="Select Table:").pack(anchor="w", pady=(15, 0))
        self.delete_row_table_var = tk.StringVar()
        self.delete_row_table_dropdown = ttk.Combobox(frame, textvariable=self.delete_row_table_var, state="readonly", width=30)
        self.delete_row_table_dropdown.pack(anchor="w")
        self.delete_row_table_dropdown.bind("<<ComboboxSelected>>", self.on_delete_row_table_selected)
        self.all_table_dropdowns.append(self.delete_row_table_dropdown)

        self.delete_fields_frame = tk.Frame(frame)
        self.delete_fields_frame.pack(anchor="w", pady=10, fill="x")
        self.delete_entries = {}

        tk.Button(frame, text="Delete Matching Row(s)", command=self.on_delete_row, bg="#d9534f", fg="white").pack(anchor="w")

    def on_delete_row_table_selected(self, event=None):
        for widget in self.delete_fields_frame.winfo_children():
            widget.destroy()
        self.delete_entries = {}
        table = self.delete_row_table_var.get()
        if not table:
            return
        columns = get_table_columns(self.prefix, table)
        self.delete_col_types = {c["name"]: c["type"] for c in columns}
        for col in columns:
            label_text = col["name"]
            if col["type"] in ("DATE", "TIMESTAMP", "TIMESTAMP(6)"):
                label_text += " (YYYY-MM-DD)"
            row = tk.Frame(self.delete_fields_frame)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=label_text, width=28, anchor="w").pack(side="left")
            entry = tk.Entry(row, width=30)
            entry.pack(side="left")
            self.delete_entries[col["name"]] = entry

    def on_delete_row(self):
        table = self.delete_row_table_var.get()
        if not table:
            self.toast.show("Select a table first.", False)
            return
        where_columns, where_values = [], []
        for col, entry in self.delete_entries.items():
            val = entry.get().strip()
            if val != "":
                where_columns.append(col)
                where_values.append(val)
        if not where_columns:
            self.toast.show("Fill in at least one field to identify the row(s, False) to delete.")
            return
        if not messagebox.askyesno("Confirm Delete", "Are you sure? This cannot be undone."):
            return
        success, message = delete_rows(self.prefix, table, where_columns, where_values, self.delete_col_types)
        if success:
            self.toast.show(message, True)
            for entry in self.delete_entries.values():
                entry.delete(0, tk.END)
        else:
            self.toast.show(friendly_error(message), False)

    def build_account_tab(self, frame):
        tk.Label(frame, text="Account Settings", font=("Arial", 14, "bold")).pack(anchor="w")
        tk.Label(frame, text=f"Logged in as: {self.username}").pack(anchor="w", pady=(10, 20))

        reset_section = tk.LabelFrame(frame, text="Reset Password", padx=10, pady=10)
        reset_section.pack(fill="x", pady=(0, 20), anchor="w")
        tk.Label(reset_section, text="New Password:").grid(row=0, column=0, sticky="w")
        self.new_password_entry = tk.Entry(reset_section, width=27, show="*")
        self.new_password_entry.grid(row=0, column=1, padx=5)
        tk.Button(reset_section, text="Update Password", command=self.on_change_password,
                  bg="#4CAF50", fg="white").grid(row=1, column=1, sticky="w", pady=8)

        tk.Button(frame, text="Logout", command=self.on_logout, bg="#777", fg="white").pack(anchor="w", pady=(0, 20))

        danger_section = tk.LabelFrame(frame, text="Delete Account", fg="#dc2626", padx=10, pady=10,
                                        bg="#fef2f2")
        danger_section.protected_color = True  # skip this subtree when tinting the tab background
        danger_section.pack(fill="x", anchor="w")
        tk.Label(danger_section, text="Warning: this permanently deletes your account AND every table\nyou've created. This cannot be undone.",
                 fg="#991b1b", bg="#fef2f2", justify="left").pack(anchor="w", pady=(0, 10))
        tk.Label(danger_section, text="Confirm your password:", bg="#fef2f2").pack(anchor="w")
        self.delete_account_password_entry = tk.Entry(danger_section, width=27, show="*")
        self.delete_account_password_entry.pack(anchor="w", pady=(0, 10))
        tk.Button(danger_section, text="Delete My Account", command=self.on_delete_account,
                  bg="#d9534f", fg="white").pack(anchor="w")

    def on_delete_account(self):
        password = self.delete_account_password_entry.get()
        if not password:
            self.toast.show("Enter your password to confirm.", False)
            return
        if not messagebox.askyesno("Confirm Account Deletion",
                                    "Are you ABSOLUTELY sure? This permanently deletes your account and every table you created. This cannot be undone."):
            return
        success, message = delete_account(self.username, self.prefix, password)
        if success:
            self.toast.show(message, True)
            self.root.after(1200, lambda: LoginWindow(self.root, lambda username: DBMSApp(self.root, username)))
        else:
            self.toast.show(friendly_error(message), False)

    def on_change_password(self):
        new_password = self.new_password_entry.get()
        if not new_password:
            self.toast.show("Enter a new password.", False)
            return
        success, message = change_password(self.username, new_password)
        if success:
            self.toast.show(message, True)
            self.new_password_entry.delete(0, tk.END)
        else:
            self.toast.show(friendly_error(message), False)

    def on_logout(self):
        if messagebox.askyesno("Logout", "Log out now?"):
            # Reuse the SAME window instead of creating a second Tk() - creating
            # a second root and calling mainloop() again while the first is
            # still running is invalid in Tkinter and was why Logout appeared broken.
            LoginWindow(self.root, lambda username: DBMSApp(self.root, username))

    def build_query_log_panel(self):
        frame = self.query_log_panel
        tk.Label(frame, text="Behind the Scenes", font=("Arial", 13, "bold"), bg="#ffffff").pack(anchor="w", padx=15, pady=(15, 0))
        tk.Label(frame, text="Query Log", font=("Arial", 10), fg="#666", bg="#ffffff").pack(anchor="w", padx=15, pady=(0, 10))
        tk.Label(frame, text="Shows the actual SQL that ran, most recent first. This panel is read-only.",
                 fg="#666", bg="#ffffff", wraplength=300, justify="left").pack(anchor="w", padx=15, pady=(0, 10))

        self.logging_toggle_btn = tk.Button(frame, text="Query Logging: ON (click to disable)",
                                             bg="#4CAF50", fg="white", command=self.toggle_logging)
        self.logging_toggle_btn.pack(anchor="w", padx=15, pady=(0, 8), fill="x")

        tk.Button(frame, text="Refresh", command=self.refresh_query_log).pack(anchor="w", padx=15, pady=(0, 10))

        text_container = tk.Frame(frame, bg="#ffffff")
        text_container.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        self.query_log_text = tk.Text(text_container, wrap="word", width=38)
        log_scroll = ttk.Scrollbar(text_container, orient="vertical", command=self.query_log_text.yview)
        self.query_log_text.configure(yscrollcommand=log_scroll.set)
        self.query_log_text.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")
        self.query_log_text.config(state="disabled")

    def toggle_logging(self):
        global LOGGING_ENABLED
        LOGGING_ENABLED = not LOGGING_ENABLED
        if LOGGING_ENABLED:
            self.logging_toggle_btn.config(text="Query Logging: ON (click to disable)", bg="#4CAF50")
        else:
            self.logging_toggle_btn.config(text="Query Logging: OFF (click to enable)", bg="#999999")
        self.toast.show(f"Query logging turned {'ON' if LOGGING_ENABLED else 'OFF'}", True)

    def refresh_query_log(self):
        self.query_log_text.config(state="normal")
        self.query_log_text.delete("1.0", tk.END)
        if not QUERY_LOG:
            self.query_log_text.insert(tk.END, "No queries logged yet - try creating a table or inserting a row.")
        else:
            for entry in reversed(QUERY_LOG[-50:]):
                self.query_log_text.insert(tk.END, f"[{entry['timestamp']}] {entry['action']}\n")
                self.query_log_text.insert(tk.END, f"  {entry['sql']}\n")
                if entry['params']:
                    self.query_log_text.insert(tk.END, f"  Values: {', '.join(entry['params'])}\n")
                self.query_log_text.insert(tk.END, "\n")
        self.query_log_text.config(state="disabled")

    def refresh_table_dropdowns(self):
        tables = get_table_names(self.prefix)
        for dropdown in self.all_table_dropdowns:
            current_value = dropdown.get()
            dropdown["values"] = tables
            if current_value and current_value not in tables:
                # The previously selected table no longer exists (e.g. it was
                # just dropped/renamed) - clear the stale text instead of
                # leaving it displayed as if it were still selectable.
                dropdown.set("")


if __name__ == "__main__":
    ensure_users_table()
    root = tk.Tk()

    # Global theme: sets the default background/foreground/font for every plain
    # Frame, Label, and Button that doesn't explicitly override it (the colored
    # category buttons and action buttons keep their own explicit colors).
    BG_MAIN = "#f8fafc"
    TEXT_MAIN = "#1e293b"

    # tk_setPalette actually rewrites Tk's default color scheme and reliably
    # recolors every plain Frame/Label/Button - option_add alone did not
    # visibly apply on all platforms, so this replaces it.
    root.tk_setPalette(background=BG_MAIN, foreground=TEXT_MAIN,
                        activeBackground=BG_MAIN, activeForeground=TEXT_MAIN)
    root.option_add('*Font', 'Arial 10')
    root.configure(bg=BG_MAIN)

    style = ttk.Style()
    style.theme_use('clam')
    style.configure('TCombobox', fieldbackground='white', background=BG_MAIN)
    style.configure('Treeview', background='white', fieldbackground='white', rowheight=26)
    style.configure('Treeview.Heading', background='#e2e8f0', font=('Arial', 10, 'bold'))

    LoginWindow(root, lambda username: DBMSApp(root, username))
    root.mainloop()