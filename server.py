import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import ssl
import sys
import time
import unicodedata
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email import policy
from email.errors import MessageError
from email.parser import BytesParser
from html import escape
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from math import ceil
from pathlib import Path
from tempfile import NamedTemporaryFile
from threading import BoundedSemaphore, Lock
from urllib.parse import parse_qs, quote, urlsplit
from zipfile import BadZipFile, ZipFile
from zoneinfo import ZoneInfo

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DATA_DIR = Path(os.environ.get('DATA_DIR', 'data'))
KEY_DIR = Path(os.environ.get('KEY_DIR', DATA_DIR))
TLS_DIR = Path(os.environ.get('TLS_DIR', 'tls'))
TLS_CERT_DIR = Path(os.environ.get('TLS_CERT_DIR', TLS_DIR))
DB_PATH = DATA_DIR / 'portal.db'
KEY_PATH = KEY_DIR / 'aes.key'
CERT_PATH = TLS_CERT_DIR / 'server.crt'
PRIVATE_KEY_PATH = TLS_DIR / 'server.key'
HOST = os.environ.get('HOST', '127.0.0.1')
SYSTEM_NAME = 'CifraDoc'
BRASILIA = ZoneInfo('America/Sao_Paulo')
UTC_TIMESTAMP_FORMAT = '%Y-%m-%d %H:%M:%S UTC'
REQUEST_TIMEOUT = 8

MAX_FORM_BYTES = 52 * 1024
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_MULTIPART_BYTES = MAX_UPLOAD_BYTES + 8 * 1024
FILE_TYPES = {
    '.pdf': 'application/pdf',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.txt': 'text/plain',
}
WINDOWS_DEVICE_NAMES = {'CON', 'PRN', 'AUX', 'NUL'} | {
    f'{device}{number}' for device in ('COM', 'LPT') for number in '123456789¹²³'
}

SESSION_SECONDS = 3600
LOGIN_CSRF_COOKIE = '__Host-portal_login'
LEGACY_SCRYPT_N = 2**14
SCRYPT_N = 2**15
SCRYPT_P = 3
DUMMY_SALT = secrets.token_bytes(16)
DUMMY_DIGEST = secrets.token_bytes(32)

MAX_FAILURES = 3
FAILURE_WINDOW_SECONDS = 90
BLOCK_SECONDS = 60

failures = {}
blocked_until = {}
security_lock = Lock()

sessions = {}
session_lock = Lock()


def utc_now():
    return datetime.now(timezone.utc).strftime(UTC_TIMESTAMP_FORMAT)


def brasilia_time(stored_utc):
    time_utc = datetime.strptime(stored_utc, UTC_TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    return time_utc.astimezone(BRASILIA).strftime('%d/%m/%Y %H:%M:%S')


def db():
    """Abre conexão independente por requisição; fecha sempre após uso."""
    con = sqlite3.connect(DB_PATH, timeout=3)
    con.execute('PRAGMA foreign_keys=ON')
    return con


@contextmanager
def connection():
    con = db()
    try:
        with con:
            yield con
    finally:
        con.close()


def password_digest(password, salt, cost=SCRYPT_N):
    """Scrypt com salt por usuário: não armazenamos senhas em texto puro."""
    parallelization = 1 if cost == LEGACY_SCRYPT_N else SCRYPT_P
    return hashlib.scrypt(
        password.encode('utf-8'),
        salt=salt,
        n=cost,
        r=8,
        p=parallelization,
        maxmem=64 * 1024 * 1024,
        dklen=32,
    )


def authenticate(ip, username, password):
    """Serializa validação e bloqueio para que logins concorrentes respeitem o mesmo limite."""
    with security_lock:
        now = time.monotonic()
        for address, deadline in list(blocked_until.items()):
            if deadline <= now:
                del blocked_until[address]
        for address, attempts in list(failures.items()):
            if now - attempts[-1] > FAILURE_WINDOW_SECONDS:
                del failures[address]
        if ip in blocked_until:
            record_event(ip, 'LOGIN_BLOQUEADO', 'IP temporariamente bloqueado após tentativas incorretas')
            return None, max(1, ceil(blocked_until[ip] - now))
        with connection() as con:
            user = con.execute(
                'SELECT id,username,salt,passhash,role,scrypt_n FROM users WHERE username=?',
                (username,),
            ).fetchone()
            salt, digest, cost = (user[2], user[3], user[5]) if user else (DUMMY_SALT, DUMMY_DIGEST, SCRYPT_N)
            valid = hmac.compare_digest(password_digest(password, salt, cost), digest) and user is not None
            if valid and cost == LEGACY_SCRYPT_N:
                salt = secrets.token_bytes(16)
                con.execute(
                    'UPDATE users SET salt=?,passhash=?,scrypt_n=? WHERE id=?',
                    (salt, password_digest(password, salt), SCRYPT_N, user[0]),
                )
            if valid:
                messages = [store_event(con, ip, 'LOGIN_OK', 'Autenticação concluída')]
            else:
                attempts = [t for t in failures.get(ip, ()) if now - t <= FAILURE_WINDOW_SECONDS] + [now]
                messages = [store_event(con, ip, 'LOGIN_FALHOU', 'Credencial incorreta')]
                if len(attempts) >= MAX_FAILURES:
                    messages.append(store_event(con, ip, 'DETECCAO_FORCA_BRUTA',
                                                f'Limiar atingido. IP bloqueado por {BLOCK_SECONDS} segundos.'))
        if valid:
            failures.pop(ip, None)
        elif len(attempts) >= MAX_FAILURES:
            blocked_until[ip] = time.monotonic() + BLOCK_SECONDS
            failures.pop(ip, None)
        else:
            failures[ip] = attempts
        for message in messages:
            print(message, flush=True)
        return user if valid else None, 0


def encrypt_note(user_id, title, body):
    payload = json.dumps({'title': title, 'body': body}, ensure_ascii=False).encode('utf-8')
    nonce = os.urandom(12)
    cipher = AESGCM(KEY).encrypt(nonce, payload, f'usuario:{user_id}'.encode())
    return nonce, cipher


def decrypt_note(user_id, nonce, ciphertext):
    raw = AESGCM(KEY).decrypt(nonce, ciphertext, f'usuario:{user_id}'.encode())
    return json.loads(raw.decode('utf-8'))


def encrypt_file(owner_id, filename, content):
    cipher = AESGCM(KEY)
    nonce = os.urandom(12)
    name_nonce = os.urandom(12)
    ciphertext = cipher.encrypt(nonce, content, f'portal-file-v1:conteudo:{owner_id}'.encode())
    name_aad = f'portal-file-v1:nome:{owner_id}'.encode() + nonce
    encrypted_name = cipher.encrypt(name_nonce, filename.encode('utf-8'), name_aad)
    return nonce, ciphertext, name_nonce, encrypted_name


def decrypt_filename(owner_id, nonce, name_nonce, encrypted_name):
    name_aad = f'portal-file-v1:nome:{owner_id}'.encode() + nonce
    return AESGCM(KEY).decrypt(name_nonce, encrypted_name, name_aad).decode('utf-8')


def document_id(query):
    ids = parse_qs(
        query, strict_parsing=True, keep_blank_values=True, max_num_fields=3,
    ).get('id', [])
    if len(ids) != 1 or not re.fullmatch(r'[0-9]{1,19}', ids[0]):
        raise ValueError('ID inválido')
    identifier = int(ids[0])
    if not 1 <= identifier <= 2**63 - 1:
        raise ValueError('ID inválido')
    return identifier


def parse_upload_parts(content_type, body):
    mime_headers = ('Content-Type: ' + content_type + '\r\n\r\n').encode('ascii')
    message = BytesParser(policy=policy.default).parsebytes(mime_headers + body)
    if message.defects or message['Content-Type'].defects or not message.is_multipart():
        raise ValueError('Esperado um formulário multipart completo')
    fields = {}
    for part in message.iter_parts():
        dispositions = [
            value for name, value in part.raw_items()
            if name.lower() == 'content-disposition'
        ]
        if (
            len(dispositions) != 1
            or part.defects
            or part.is_multipart()
            or part.get('Content-Transfer-Encoding') is not None
        ):
            raise ValueError('Parte do formulário inválida')
        disposition_text = dispositions[0].encode('ascii', 'surrogateescape').decode('utf-8')
        disposition = policy.default.header_factory('Content-Disposition', disposition_text)
        if disposition.defects or disposition.content_disposition != 'form-data':
            raise ValueError('Disposição do formulário inválida')
        field = disposition.params.get('name')
        filename = disposition.params.get('filename')
        if field not in ('csrf', 'submission_id', 'file') or field in fields:
            raise ValueError('Campo do formulário inválido')
        raw = part.get_payload(decode=True)
        if field == 'file':
            fields[field] = (filename, raw)
        elif filename is None and len(raw) <= 128:
            fields[field] = raw.decode('ascii')
        else:
            raise ValueError('Campo do formulário inválido')
    return fields


def valid_upload(filename, content):
    if not filename or not content or len(filename.encode('utf-8')) > 255:
        return False
    if (
        filename != filename.strip(' .')
        or filename.partition('.')[0].upper() in WINDOWS_DEVICE_NAMES
        or any(
            char in '/\\<>:"|?*' or unicodedata.category(char).startswith('C')
            for char in filename
        )
    ):
        return False
    suffix = Path(filename).suffix.lower()
    if suffix == '.pdf':
        return bool(re.match(rb'%PDF-[0-9]\.[0-9](?:\r|\n)', content))
    if suffix == '.docx':
        try:
            with ZipFile(BytesIO(content)) as package:
                return {'[Content_Types].xml', 'word/document.xml'} <= set(package.namelist())
        except (BadZipFile, UnicodeError, NotImplementedError, ValueError):
            return False
    if suffix == '.txt':
        try:
            return '\x00' not in content.decode('utf-8')
        except UnicodeDecodeError:
            return False
    return False


def write_key_file(path, content, mode):
    """Grava primeiro no mesmo diretório para publicar um arquivo completo."""
    with NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        temporary_path = Path(temporary.name)
        try:
            temporary.write(content)
            temporary.close()
            temporary_path.chmod(mode)
            temporary_path.replace(path)
        finally:
            temporary_path.unlink(missing_ok=True)


def load_document_key(con):
    KEY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    KEY_DIR.chmod(0o700)
    legacy_path = DATA_DIR / 'aes.key'
    source = KEY_PATH if KEY_PATH.exists() else legacy_path
    if source.exists():
        key = source.read_bytes()
        if len(key) != 32:
            raise RuntimeError('A chave AES precisa ter 32 bytes.')
        source.chmod(0o600)
        if source != legacy_path and legacy_path.exists() and legacy_path.read_bytes() != key:
            raise RuntimeError('As chaves AES atual e antiga divergem. Confirme qual pertence a este banco.')
    else:
        if con.execute('SELECT 1 FROM notes UNION ALL SELECT 1 FROM files LIMIT 1').fetchone():
            raise RuntimeError('Há documentos cifrados. Restaure a chave AES original antes de iniciar.')
        key = secrets.token_bytes(32)
    if not KEY_PATH.exists():
        write_key_file(KEY_PATH, key, 0o600)
    return key


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(DATA_DIR, 0o700)
    with connection() as con:
        con.execute('BEGIN IMMEDIATE')
        con.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            salt BLOB NOT NULL, passhash BLOB NOT NULL, role TEXT NOT NULL,
            scrypt_n INTEGER NOT NULL DEFAULT 16384)''')
        if 'scrypt_n' not in {column[1] for column in con.execute('PRAGMA table_info(users)')}:
            con.execute('ALTER TABLE users ADD COLUMN scrypt_n INTEGER NOT NULL DEFAULT 16384')
        con.execute('''CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL,
            nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id))''')
        con.execute('''CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL,
            nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
            name_nonce BLOB NOT NULL, encrypted_name BLOB NOT NULL,
            created_at TEXT NOT NULL, submission_id TEXT,
            UNIQUE(owner_id, submission_id),
            FOREIGN KEY(owner_id) REFERENCES users(id))''')
        con.execute('''CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL,
            ip TEXT NOT NULL, event_type TEXT NOT NULL, description TEXT NOT NULL)''')
        if 'submission_id' not in {column[1] for column in con.execute('PRAGMA table_info(notes)')}:
            con.execute('ALTER TABLE notes ADD COLUMN submission_id TEXT')
        con.execute('CREATE UNIQUE INDEX IF NOT EXISTS notes_submission ON notes (owner_id, submission_id)')
        key = load_document_key(con)
        demos = (
            ('admin', os.environ.get('DEMO_ADMIN_PASSWORD', 'AdminLab!2026'), 'admin'),
            ('aluno', os.environ.get('DEMO_USER_PASSWORD', 'AlunoLab!2026'), 'user'),
            ('colega', os.environ.get('DEMO_OTHER_PASSWORD', 'ColegaLab!2026'), 'user'),
        )
        for username, password, role in demos:
            if not 1 <= len(password) <= 300:
                raise RuntimeError(f'Senha da conta de laboratório {username} precisa de 1 a 300 caracteres.')
            if not con.execute('SELECT 1 FROM users WHERE username=?', (username,)).fetchone():
                salt = secrets.token_bytes(16)
                con.execute('INSERT INTO users (username,salt,passhash,role,scrypt_n) VALUES (?,?,?,?,?)',
                            (username, salt, password_digest(password, salt), role, SCRYPT_N))
    return key


def generate_cert_if_needed():
    TLS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    TLS_DIR.chmod(0o700)
    TLS_CERT_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    legacy_cert = TLS_DIR / 'server.crt'
    source = CERT_PATH if CERT_PATH.exists() else legacy_cert
    if source.exists():
        if not PRIVATE_KEY_PATH.exists():
            raise RuntimeError('Certificado TLS presente sem chave privada correspondente.')
        current = x509.load_pem_x509_certificate(source.read_bytes())
        if not current.not_valid_before_utc <= datetime.now(timezone.utc) <= current.not_valid_after_utc:
            raise RuntimeError('Certificado TLS fora da validade. Confira o relógio do sistema e a configuração.')
        PRIVATE_KEY_PATH.chmod(0o600)
        if source != CERT_PATH:
            write_key_file(CERT_PATH, source.read_bytes(), 0o644)
        return
    if PRIVATE_KEY_PATH.exists():
        key = serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise RuntimeError('É necessária uma chave RSA para gerar o certificado TLS de laboratório.')
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        write_key_file(PRIVATE_KEY_PATH, key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()), 0o600)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName('localhost'), x509.DNSName('server'),
            x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
        ]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    write_key_file(CERT_PATH, cert.public_bytes(serialization.Encoding.PEM), 0o644)


def store_event(con, ip, event_type, description):
    occurred_at = utc_now()
    con.execute('INSERT INTO events (occurred_at,ip,event_type,description) VALUES (?,?,?,?)',
                (occurred_at, ip, event_type, description))
    return f'{occurred_at} [SEGURANÇA] {event_type}: {description} (IP {ip})'


def record_event(ip, event_type, description):
    """Log sem armazenar senhas, notas ou tokens de sessão."""
    with connection() as con:
        message = store_event(con, ip, event_type, description)
    print(message, flush=True)


CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
    margin: 0;
    background: #121212;
    color: #e5e5e5;
    font: 1rem/1.5 Arial, sans-serif;
}
header {
    background: #1c1c1c;
    border-bottom: 1px solid #444;
}
.page-width {
    width: min(calc(100% - 2rem), 65rem);
    margin-inline: auto;
}
.header-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: .75rem 1.5rem;
    padding-block: 1rem;
}
.site-name { font-size: 1.125rem; }
.nav {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: .5rem 1.25rem;
}
.nav form { margin: 0; }
main { padding-block: 1.75rem 2.5rem; }
h1 {
    margin: 0 0 1rem;
    font-size: 1.65rem;
    overflow-wrap: anywhere;
}
h2 {
    margin: 0 0 .75rem;
    font-size: 1.18rem;
}
h3 {
    margin: 0 0 .75rem;
    font-size: 1.02rem;
}
.panel {
    background: #1c1c1c;
    padding: clamp(.875rem, 3vw, 1.25rem);
    border: 1px solid #444;
}
.panel + .panel { margin-top: 1.25rem; }
.login-layout { max-width: 26rem; }
.document-forms {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 1.5rem;
}
.upload-form {
    border-left: 1px solid #444;
    padding-left: 1.5rem;
}
label {
    display: block;
    font-weight: 700;
}
input:not([type="hidden"]), textarea {
    display: block;
    width: 100%;
    margin: .25rem 0 .875rem;
    padding: .5rem;
    border: 1px solid #444;
    border-radius: 0;
    background: #121212;
    color: #fff;
    font: inherit;
    font-weight: 400;
}
textarea {
    min-height: 7rem;
    resize: vertical;
}
button, input[type="file"]::file-selector-button {
    padding: .45rem .8rem;
    border: 1px solid #444;
    border-radius: 0;
    background: #ADAFB3;
    color: #000;
    font: inherit;
    cursor: pointer;
}
input[type="file"]::file-selector-button {
    margin-right: .5rem;
    padding: .25rem .5rem;
}
a {
    color: inherit;
    text-underline-offset: .16em;
}
:focus-visible {
    outline: 2px solid #ADAFB3;
    outline-offset: 3px;
}
.muted { color: #e5e5e5; }
.help {
    margin: 0 0 .875rem;
    font-size: .9375rem;
}
.error, .success {
    padding: .625rem;
    border: 1px solid #444;
    border-left-width: 3px;
    border-left-color: #ADAFB3;
    background: #1c1c1c;
    color: #fff;
    font-weight: 700;
}
.table-scroll { overflow-x: auto; }
table {
    width: 100%;
    border-collapse: collapse;
}
th, td {
    padding: .625rem;
    border-bottom: 1px solid #444;
    text-align: left;
    vertical-align: top;
    overflow-wrap: anywhere;
}
th { background: #242424; }
.documents-table { min-width: 35rem; }
.documents-table td:nth-child(2) { width: 38%; }
.documents-table th:first-child, .document-date, .document-size, .document-action {
    white-space: nowrap;
}
.document-meta { display: none; }
pre {
    margin-top: 0;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    font: inherit;
}
@media (max-width: 40rem) {
    .nav { column-gap: .875rem; }
    .document-forms { grid-template-columns: minmax(0, 1fr); }
    .upload-form {
        border-left: 0;
        border-top: 1px solid #444;
        padding: 1rem 0 0;
    }
    .documents-table { min-width: 0; }
    .documents-table td:nth-child(2) { width: auto; }
    .document-type, .document-date, .document-size { display: none; }
    .document-meta {
        display: block;
        color: #e5e5e5;
    }
}
"""


def page(title, contents, session=None):
    nav = ''
    if session:
        logs = '<a href="/admin/logs">Registros</a>' if session['role'] == 'admin' else ''
        nav = (
            '<nav class="nav" aria-label="Navegação principal">'
            '<a href="/notes">Documentos</a>'
            '<a href="/notes#novo-documento">Novo documento</a>'
            f'{logs}<span class="muted">{escape(session["username"])}</span>'
            '<form method="post" action="/logout">'
            f'<input type="hidden" name="csrf" value="{escape(session["csrf"])}">'
            '<button type="submit" class="button-plain">Sair</button>'
            '</form></nav>'
        )
    login_page = title == SYSTEM_NAME and session is None
    main_class = 'page-width login-layout' if login_page else 'page-width'
    browser_title = SYSTEM_NAME if login_page else f'{title} | {SYSTEM_NAME}'
    return (
        f'<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{escape(browser_title)}</title><style>{CSS}</style></head>'
        '<body><header><div class="page-width header-bar">'
        f'<strong class="site-name">{SYSTEM_NAME}</strong>{nav}</div></header>'
        f'<main class="{main_class}"><h1>{escape(title)}</h1>{contents}</main></body></html>'
    )


def format_file_size(size):
    if size is None:
        return '—'
    if size >= 1024**2:
        return f'{size / 1024**2:.1f} MiB'.replace('.', ',')
    if size >= 1024:
        return f'{size / 1024:.1f} KiB'.replace('.', ',')
    return f'{size} B'


def documents_page(session, notes, files, upload_succeeded=False):
    entries = [
        (created, note_id, title, 'Nota de texto', '/notes/view', None)
        for note_id, title, created in notes
    ]
    entries.extend(
        (
            created, file_id, name,
            Path(name).suffix[1:].upper() if name else 'Arquivo',
            '/files/download', size,
        )
        for file_id, name, created, size in files
    )
    rows = []
    for created, document_id, name, kind, route, size in sorted(entries, key=lambda entry: entry[:2], reverse=True):
        if name is None:
            label = 'Documento com falha de integridade'
            action = '—'
        else:
            href = f'{route}?id={document_id}'
            label = f'<a href="{href}">{escape(name)}</a>'
            if route == '/notes/view':
                action = f'<a href="{href}#conteudo">Abrir</a>'
            else:
                action = f'<a href="{href}#arquivo">Baixar</a>'
        kind = escape(kind)
        created = brasilia_time(created)
        size_label = format_file_size(size)
        metadata = f'{kind} · {size_label} · {created}' if size is not None else f'{kind} · {created}'
        rows.append(f'<tr><td>{document_id}</td><td>{label}'
                    f'<small class="document-meta">{metadata} (Brasília)</small></td>'
                    f'<td class="document-type">{kind}</td><td class="document-size">{size_label}</td>'
                    f'<td class="document-date">{created}</td>'
                    f'<td class="document-action">{action}</td></tr>')
    if rows:
        listing = (
            '<div class="table-scroll" role="region" aria-label="Documentos salvos" tabindex="0">'
            '<table class="documents-table"><thead><tr><th scope="col">ID</th>'
            '<th scope="col">Nome ou título</th>'
            '<th class="document-type" scope="col">Tipo</th>'
            '<th class="document-size" scope="col">Tamanho</th>'
            '<th class="document-date" scope="col">Data (Brasília)</th>'
            '<th class="document-action" scope="col">Ação</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>'
        )
    else:
        listing = '<p>Nenhum documento salvo.</p>'
    notice = '<p class="success" role="status">Arquivo enviado e criptografado com sucesso</p>' if upload_succeeded else ''
    csrf_field = f'<input type="hidden" name="csrf" value="{escape(session["csrf"])}">'
    contents = (
        f'{notice}<section class="panel">{listing}</section>'
        '<section class="panel" aria-labelledby="novo-documento">'
        '<h2 id="novo-documento">Novo documento</h2><div class="document-forms">'
        '<form method="post" action="/notes">'
        f'<h3>Nota de texto</h3>{csrf_field}'
        f'<input type="hidden" name="submission_id" value="{secrets.token_urlsafe(24)}">'
        '<label for="note-title">Título</label><input id="note-title" name="title" maxlength="80" required>'
        '<label for="note-body">Conteúdo</label>'
        '<textarea id="note-body" name="body" maxlength="4000" required></textarea>'
        '<button type="submit">Salvar nota</button></form>'
        '<form class="upload-form" method="post" action="/files" enctype="multipart/form-data">'
        f'<h3>Enviar arquivo</h3>{csrf_field}'
        f'<input type="hidden" name="submission_id" value="{secrets.token_urlsafe(24)}">'
        '<label for="upload-file">Arquivo</label>'
        '<input id="upload-file" type="file" name="file" accept=".pdf,.docx,.txt" '
        'aria-describedby="upload-rules" required>'
        '<p class="help muted" id="upload-rules">PDF, DOCX ou TXT. Limite de 2 MiB por arquivo.</p>'
        '<button type="submit">Enviar arquivo</button></form></div></section>'
    )
    return page('Documentos', contents, session)


class PortalHandler(BaseHTTPRequestHandler):
    server_version = 'PortalSeguro'
    sys_version = ''

    def log_message(self, format, *args):
        # O log padrão reflete a linha da requisição. Os eventos abaixo usam mensagens fixas.
        pass

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except sqlite3.Error:
            print(f'{utc_now()} [ERRO] Falha temporária no banco de dados.', file=sys.stderr, flush=True)
            self.respond(503, page('Serviço temporariamente indisponível', '<p>Tente novamente em instantes.</p>'))
        except (ConnectionError, TimeoutError, ssl.SSLError):
            self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        self.close_connection = True
        self.respond(code, page('Requisição recusada', '<p>Confira o endereço e o formato da requisição.</p>'))

    def respond(
        self, status, content, *, cookie=None, redirect=None, retry_after=None,
        plain_text=False, download_name=None,
    ):
        if download_name is None:
            raw = b'' if redirect is not None else content.encode('utf-8')
            mime = 'text/plain; charset=utf-8' if plain_text or redirect else 'text/html; charset=utf-8'
        else:
            raw = content
            suffix = Path(download_name).suffix.lower()
            mime = FILE_TYPES[suffix]
        self.send_response(status)
        self.send_header('Content-Type', mime)
        if download_name is not None:
            fallback = download_name if re.fullmatch(r'[A-Za-z0-9._ -]+', download_name) else f'arquivo{suffix}'
            encoded_name = quote(download_name, safe='')
            self.send_header('Content-Disposition', f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded_name}")
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header(
            'Content-Security-Policy',
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
            "base-uri 'none'; frame-ancestors 'none'",
        )
        if cookie is not None:
            for value in cookie if isinstance(cookie, tuple) else (cookie,):
                self.send_header('Set-Cookie', value)
        if redirect is not None:
            self.send_header('Location', redirect)
        if retry_after is not None:
            self.send_header('Retry-After', str(retry_after))
        try:
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(raw)
        except (ConnectionError, TimeoutError, ssl.SSLError):
            self.close_connection = True

    def cookie_value(self, name):
        try:
            cookie = SimpleCookie()
            cookie.load(self.headers.get('Cookie', ''))
            return cookie[name].value if name in cookie else ''
        except CookieError:
            return ''

    def current_session(self):
        session_token = self.cookie_value('session')
        with session_lock:
            record = sessions.get(session_token)
            if not record:
                return None
            if record['expires'] <= time.monotonic():
                del sessions[session_token]
                return None
            return record.copy()

    def require_login(self):
        session = self.current_session()
        if not session:
            self.respond(302, '', redirect='/login')
        return session

    def read_body(self, limit, media_type):
        try:
            lengths = self.headers.get_all('Content-Length', [])
            if (
                self.headers.get('Transfer-Encoding')
                or len(lengths) != 1
                or not re.fullmatch(r'[0-9]{1,10}', lengths[0])
            ):
                raise ValueError('Tamanho da requisição inválido')
            length = int(lengths[0])
            if length > limit:
                description = 'O arquivo deve ter até 2 MiB.' if media_type == 'multipart/form-data' else 'Dados muito grandes.'
                self.respond(413, page('Limite excedido', f'<p>{description}</p>'))
                return None
            content_types = self.headers.get_all('Content-Type', [])
            if len(content_types) != 1 or self.headers.get_content_type() != media_type:
                self.respond(415, page('Formato inválido', '<p>Use um formulário web.</p>'))
                return None
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('Corpo incompleto')
            return raw
        except ValueError:
            self.respond(400, page('Entrada inválida', '<p>Não foi possível ler os dados.</p>'))
        except TimeoutError:
            self.respond(408, page('Tempo de espera esgotado', '<p>Envie o formulário novamente.</p>'))
        return None

    def read_form(self):
        raw = self.read_body(MAX_FORM_BYTES, 'application/x-www-form-urlencoded')
        if raw is None:
            return None
        try:
            encoded = raw.decode('utf-8')
            if re.search(r'%(?![0-9a-fA-F]{2})', encoded):
                raise ValueError('Percent-encoding inválido')
            fields = parse_qs(
                encoded, keep_blank_values=True, strict_parsing=True, errors='strict',
                max_num_fields=8,
            )
            if any(len(values) != 1 for values in fields.values()):
                raise ValueError('Campos repetidos')
            return {key: values[0] for key, values in fields.items()}
        except ValueError:
            self.respond(400, page('Entrada inválida', '<p>Não foi possível ler os dados.</p>'))
            return None

    def check_csrf(self, form, expected, session=None):
        supplied = form.get('csrf', '')
        if not expected or not hmac.compare_digest(supplied.encode(), expected.encode()):
            record_event(self.client_address[0], 'CSRF_REJEITADO', 'Formulário sem token válido')
            self.respond(403, page('Acesso negado', '<p>O formulário expirou ou é inválido. Abra a página novamente.</p>', session))
            return False
        return True

    def request_url(self):
        try:
            url = urlsplit(self.path)
            if url.netloc or url.scheme or not url.path.startswith('/'):
                raise ValueError('Use um caminho relativo ao servidor')
            return url
        except ValueError:
            self.respond(400, page('Entrada inválida', '<p>Endereço do recurso inválido.</p>'))
            return None

    def upload_file(self, session):
        raw = self.read_body(MAX_MULTIPART_BYTES, 'multipart/form-data')
        if raw is None:
            return
        content_type = self.headers['Content-Type']
        try:
            if len(content_type) > 512 or '\r' in content_type or '\n' in content_type:
                raise ValueError('Cabeçalho multipart inválido')
            form = parse_upload_parts(content_type, raw)
        except (ValueError, MessageError, TypeError, IndexError):
            return self.respond(400, page('Envio inválido', '<p>Abra o formulário e selecione um arquivo.</p>', session))
        if not self.check_csrf(form, session['csrf'], session):
            return
        filename, content = form.get('file', (None, b''))
        if len(content) > MAX_UPLOAD_BYTES:
            return self.respond(413, page('Limite excedido', '<p>O arquivo deve ter até 2 MiB.</p>', session))
        if not valid_upload(filename, content):
            return self.respond(400, page('Arquivo inválido',
                                          '<p>Escolha um PDF, DOCX ou TXT válido, com nome e conteúdo.</p>', session))
        submission_id = form.get('submission_id')
        if submission_id is not None and not re.fullmatch(r'[A-Za-z0-9_-]{32}', submission_id):
            return self.respond(400, page('Envio inválido', '<p>Abra o formulário e envie novamente.</p>', session))
        owner_id = session['id']
        protected = encrypt_file(owner_id, filename, content)
        with connection() as con:
            cursor = con.execute('''INSERT INTO files
                (owner_id,nonce,ciphertext,name_nonce,encrypted_name,created_at,submission_id)
                VALUES (?,?,?,?,?,?,?) ON CONFLICT (owner_id, submission_id) DO NOTHING''',
                (owner_id, *protected, utc_now(), submission_id))
            event = None
            if cursor.rowcount:
                event = store_event(con, self.client_address[0], 'ARQUIVO_ENVIADO', 'Arquivo protegido foi gravado')
        if event:
            print(event, flush=True)
            with session_lock:
                active_session = sessions.get(self.cookie_value('session'))
                if active_session is not None:
                    active_session['upload_succeeded'] = True
        return self.respond(303, '', redirect='/notes')

    def download_file(self, url):
        ip = self.client_address[0]
        session = self.current_session()
        if not session:
            record_event(ip, 'ACESSO_NEGADO', 'Download solicitado sem sessão válida')
            return self.respond(302, '', redirect='/login')
        try:
            file_id = document_id(url.query)
        except ValueError:
            return self.respond(400, page('Entrada inválida', '<p>ID inválido.</p>', session))
        owner_id = session['id']
        with connection() as con:
            row = con.execute('''SELECT nonce,ciphertext,name_nonce,encrypted_name
                FROM files WHERE id=? AND owner_id=?''', (file_id, owner_id)).fetchone()
        if row is None:
            record_event(ip, 'ACESSO_NEGADO', 'Download sem permissão para o arquivo')
            return self.respond(403, page('Acesso negado',
                                          '<p class="error" role="alert">'
                                          'Você não tem permissão para acessar este documento.</p>', session))
        nonce, ciphertext, name_nonce, encrypted_name = row
        try:
            filename = decrypt_filename(owner_id, nonce, name_nonce, encrypted_name)
            aad = f'portal-file-v1:conteudo:{owner_id}'.encode()
            content = AESGCM(KEY).decrypt(nonce, ciphertext, aad)
        except (InvalidTag, ValueError, TypeError):
            record_event(ip, 'INTEGRIDADE_FALHOU', 'Falha ao verificar um arquivo')
            return self.respond(500, page('Erro de integridade', '<p>O arquivo não pôde ser validado.</p>', session))
        record_event(ip, 'ARQUIVO_BAIXADO', 'Download autorizado')
        return self.respond(200, content, download_name=filename)

    def do_GET(self):
        url = self.request_url()
        if url is None:
            return
        path = url.path
        if path == '/health':
            return self.respond(200, 'OK', plain_text=True)
        if path == '/':
            return self.respond(302, '', redirect='/notes' if self.current_session() else '/login')
        if path == '/login':
            csrf = secrets.token_urlsafe(24)
            form = (
                '<section class="panel" aria-label="Login">'
                '<form method="post" action="/login">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                '<label for="login-user">Usuário</label>'
                '<input id="login-user" name="username" required maxlength="50" '
                'autocomplete="username">'
                '<label for="login-password">Senha</label>'
                '<input id="login-password" type="password" name="password" required maxlength="300" '
                'autocomplete="current-password">'
                '<button type="submit">Entrar</button>'
                '</form></section>'
            )
            cookie = f'{LOGIN_CSRF_COOKIE}={csrf}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=600'
            return self.respond(200, page(SYSTEM_NAME, form), cookie=cookie)
        if path == '/notes':
            session = self.require_login()
            if not session:
                return
            owner_id = session['id']
            with connection() as con:
                notes = []
                for note_id, nonce, ciphertext, created_at in con.execute(
                        'SELECT id,nonce,ciphertext,created_at FROM notes WHERE owner_id=?', (owner_id,)):
                    try:
                        title = decrypt_note(owner_id, nonce, ciphertext)['title']
                    except (InvalidTag, ValueError, KeyError, TypeError):
                        title = None
                    notes.append((note_id, title, created_at))
                files = []
                # O AES-GCM acrescenta uma tag de 16 bytes à cifra.
                for file_id, nonce, name_nonce, encrypted_name, created_at, size in con.execute(
                        '''SELECT id,nonce,name_nonce,encrypted_name,created_at,length(ciphertext)-16
                        FROM files WHERE owner_id=?''', (owner_id,)):
                    try:
                        filename = decrypt_filename(owner_id, nonce, name_nonce, encrypted_name)
                    except (InvalidTag, ValueError, TypeError):
                        filename = None
                    files.append((file_id, filename, created_at, size if filename and size > 0 else None))
            with session_lock:
                active_session = sessions.get(self.cookie_value('session'))
                upload_succeeded = active_session.pop('upload_succeeded', False) if active_session is not None else False
            return self.respond(200, documents_page(session, notes, files, upload_succeeded))
        if path == '/files/download':
            return self.download_file(url)
        if path == '/notes/view':
            session = self.require_login()
            if not session:
                return
            try:
                note_id = document_id(url.query)
            except ValueError:
                return self.respond(400, page('Erro', '<p>ID inválido.</p>', session))
            with connection() as con:
                row = con.execute('SELECT nonce,ciphertext FROM notes WHERE id=? AND owner_id=?',
                                  (note_id, session['id'])).fetchone()
            if not row:
                record_event(self.client_address[0], 'ACESSO_NEGADO', 'Documento inexistente ou de outro usuário')
                return self.respond(403, page('Acesso negado',
                                              '<p class="error" role="alert">'
                                              'Você não tem permissão para acessar este documento.</p>', session))
            try:
                note = decrypt_note(session['id'], row[0], row[1])
                contents = (f'<section class="panel"><pre id="conteudo">{escape(note["body"])}</pre>'
                            '<p><a href="/notes">Voltar aos documentos</a></p></section>')
                return self.respond(200, page(note['title'], contents, session))
            except (InvalidTag, ValueError, KeyError, TypeError):
                record_event(self.client_address[0], 'INTEGRIDADE_FALHOU', 'Falha ao verificar um documento')
                return self.respond(500, page('Erro de integridade', '<p>Documento não pôde ser validado.</p>', session))
        if path == '/admin/logs':
            session = self.require_login()
            if not session:
                return
            if session['role'] != 'admin':
                record_event(self.client_address[0], 'ACESSO_NEGADO', 'Tentativa de acesso aos logs administrativos')
                return self.respond(403, page('Acesso negado', '<p class="error" role="alert">'
                                              'Somente administradores podem ver os logs.</p>', session))
            with connection() as con:
                rows = con.execute('SELECT occurred_at,ip,event_type,description FROM events ORDER BY id DESC LIMIT 80').fetchall()
            table = ''.join(f'<tr><td>{brasilia_time(occurred_at)}</td><td>{escape(ip)}</td>'
                            f'<td>{escape(event_type)}</td><td>{escape(description)}</td></tr>'
                            for occurred_at, ip, event_type, description in rows)
            contents = ('<section class="panel"><p class="help muted">Até 80 eventos recentes.</p>'
                        '<div class="table-scroll" role="region" aria-label="Eventos recentes" tabindex="0">'
                        '<table><thead><tr><th scope="col">Data (Brasília)</th><th scope="col">IP</th>'
                        '<th scope="col">Tipo</th><th scope="col">Descrição</th></tr></thead>'
                        f'<tbody>{table}</tbody></table></div></section>')
            return self.respond(200, page('Logs de segurança', contents, session))
        return self.respond(404, page('Não encontrado', '<p>Rota inexistente.</p>'))

    def do_POST(self):
        url = self.request_url()
        if url is None:
            return
        path = url.path
        if path == '/files':
            session = self.require_login()
            if session:
                return self.upload_file(session)
            return
        if path not in ('/login', '/logout', '/notes'):
            return self.respond(404, page('Não encontrado', '<p>Rota inexistente.</p>'))
        form = self.read_form()
        if form is None:
            return
        ip = self.client_address[0]
        if path == '/login':
            if not self.check_csrf(form, self.cookie_value(LOGIN_CSRF_COOKIE)):
                return
            username = form.get('username', '').strip()
            password = form.get('password', '')
            if not 1 <= len(username) <= 50 or not 1 <= len(password) <= 300:
                return self.respond(400, page('Entrada inválida', '<p>Preencha usuário e senha dentro dos limites.</p><a href="/login">Voltar</a>'))
            user, retry_after = authenticate(ip, username, password)
            if retry_after:
                return self.respond(429, page('Bloqueio temporário',
                                              f'<p>Tente entrar novamente em {retry_after} segundos.</p><a href="/login">Voltar ao login</a>'),
                                    retry_after=retry_after)
            if not user:
                return self.respond(401, page('Login incorreto', '<p class="error">Usuário ou senha inválidos.</p><a href="/login">Voltar</a>'))
            session_token = secrets.token_urlsafe(32)
            now = time.monotonic()
            session = {
                'id': user[0],
                'username': user[1],
                'role': user[4],
                'csrf': secrets.token_urlsafe(24),
                'expires': now + SESSION_SECONDS,
            }
            old_token = self.cookie_value('session')
            with session_lock:
                sessions.pop(old_token, None)
                for token, record in list(sessions.items()):
                    if record['expires'] <= now:
                        del sessions[token]
                sessions[session_token] = session
            cookie = f'session={session_token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={SESSION_SECONDS}'
            expire_login_csrf = f'{LOGIN_CSRF_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'
            return self.respond(303, '', cookie=(cookie, expire_login_csrf), redirect='/notes')
        session = self.require_login()
        if not session:
            return
        if not self.check_csrf(form, session['csrf'], session):
            return
        if path == '/logout':
            token = self.cookie_value('session')
            with session_lock:
                sessions.pop(token, None)
            return self.respond(303, '', cookie='session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0', redirect='/login')
        title = form.get('title', '').strip()
        body = form.get('body', '').strip()
        submission_id = form.get('submission_id')
        if not (1 <= len(title) <= 80 and 1 <= len(body) <= 4000):
            return self.respond(400, page('Entrada inválida', '<p>Título ou conteúdo fora dos limites.</p>', session))
        if submission_id is not None and not re.fullmatch(r'[A-Za-z0-9_-]{32}', submission_id):
            return self.respond(400, page('Entrada inválida', '<p>Abra o formulário e envie novamente.</p>', session))
        nonce, cipher = encrypt_note(session['id'], title, body)
        with connection() as con:
            cursor = con.execute('''INSERT INTO notes (owner_id,nonce,ciphertext,created_at,submission_id)
                VALUES (?,?,?,?,?) ON CONFLICT (owner_id, submission_id) DO NOTHING''',
                (session['id'], nonce, cipher, utc_now(), submission_id))
            event = store_event(con, ip, 'DOCUMENTO_CRIADO', 'Documento protegido foi gravado') if cursor.rowcount else None
        if event:
            print(event, flush=True)
        return self.respond(303, '', redirect='/notes')


class PortalServer(ThreadingHTTPServer):
    def __init__(self, address, tls):
        self.tls = tls
        self.worker_slots = BoundedSemaphore(16)
        super().__init__(address, PortalHandler)

    def process_request(self, request, client_address):
        if self.worker_slots.acquire(blocking=False):
            super().process_request(request, client_address)
        else:
            self.shutdown_request(request)

    def process_request_thread(self, request, client_address):
        # Faz o handshake na thread, com limite de espera, antes de processar HTTP.
        try:
            request.settimeout(REQUEST_TIMEOUT)
            with self.tls.wrap_socket(request, server_side=True) as secure_request:
                super().process_request_thread(secure_request, client_address)
        except (OSError, ssl.SSLError):
            self.shutdown_request(request)
        finally:
            self.worker_slots.release()

    def handle_error(self, request, client_address):
        print(f'{utc_now()} [ERRO] Requisição interrompida durante o processamento.', file=sys.stderr, flush=True)


def main():
    global KEY
    try:
        port = int(os.environ.get('PORT', '8443'))
        if not 1 <= port <= 65535:
            raise ValueError()
    except ValueError:
        print('Falha de inicialização. PORT precisa ser um inteiro entre 1 e 65535.', file=sys.stderr)
        return 1

    try:
        KEY = init_db()
        generate_cert_if_needed()
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(certfile=str(CERT_PATH), keyfile=str(PRIVATE_KEY_PATH))
        with PortalServer((HOST, port), tls) as server:
            print(f'Portal iniciado em https://{HOST}:{port} (HTTPS/TLS).', flush=True)
            server.serve_forever()
    except KeyboardInterrupt:
        return 0
    except RuntimeError as exc:
        print(f'Falha de inicialização. {exc}', file=sys.stderr)
        return 1
    except ssl.SSLError:
        print('Falha de inicialização. Confira o certificado TLS e sua chave privada.', file=sys.stderr)
        return 1
    except sqlite3.Error:
        print('Falha de inicialização. Confira o banco SQLite e as permissões do volume de dados.', file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError):
        print('Falha de inicialização. Confira a porta, os volumes, as permissões e os arquivos TLS.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
