"""central configuration - every tunable in one place, env-driven where deployment varies."""
import os
import string

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_DIR = os.path.join(APP_ROOT, "uploads")
WORDLIST_DIR = os.path.join(APP_ROOT, "wordlists")

HOST = os.getenv("ZIPPASS_HOST", "127.0.0.1")
PORT = int(os.getenv("ZIPPASS_PORT", "5000"))
MAX_UPLOAD = int(os.getenv("ZIPPASS_MAX_UPLOAD_MB", "2048")) * 1024 * 1024
TASK_RANGE = int(os.getenv("ZIPPASS_TASK_RANGE", "65536"))    # max candidates per worker task (brute/mask)
DICT_CHUNK = int(os.getenv("ZIPPASS_DICT_CHUNK", "1048576"))   # wordlist bytes per worker task
VECTOR = os.getenv("ZIPPASS_VECTOR", "1") != "0"   # numpy batch filter for zipcrypto scans
MAX_WORD_LEN = int(os.getenv("ZIPPASS_MAX_WORD_LEN", "512"))
MAX_WORKERS = int(os.getenv("ZIPPASS_MAX_WORKERS", "64"))
MAX_UPLOADS_KEPT = int(os.getenv("ZIPPASS_MAX_UPLOADS_KEPT", "50"))
MAX_JOBS_KEPT = int(os.getenv("ZIPPASS_MAX_JOBS_KEPT", "50"))

MAX_MASK_TOKENS = 64
MAX_CUSTOM_SET_LEN = 256
MAX_CHARSET_LEN = 1024
MAX_VERIFY_PASSWORDS = 10000
MAX_PASSWORD_LEN = 256
LEN_LIMIT = 64  # upper bound for candidate length settings

CHARSETS = {
    "l": string.ascii_lowercase,
    "u": string.ascii_uppercase,
    "d": string.digits,
    "s": "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~ ",
    "h": "0123456789abcdef",
    "a": string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~ ",
}

# wordlist paths must live under one of these roots; extend via env
_extra_roots = [r for r in os.getenv("ZIPPASS_WORDLIST_ROOTS", "").split(os.pathsep) if r]
ALLOWED_WORDLIST_ROOTS = [APP_ROOT] + _extra_roots
