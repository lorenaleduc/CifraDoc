"""Testes HTTPS de aceitação do Portal Seguro no laboratório da equipe."""

from collections import Counter
from dataclasses import dataclass
from html.parser import HTMLParser
import http.cookiejar
from ipaddress import ip_address
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlencode, urlsplit
from urllib.request import (
    HTTPCookieProcessor, HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener,
)

from file_test_fixture import attachment_marker, sample_attachment


HTTP_CASES = (1, 2, 3, 4, 5, 6, 7, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22)
TIMEOUT = 8
INVALID_PASSWORD = 'incorreta-para-teste-controlado'


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PortalHTML(HTMLParser):
    """Lê somente os campos e elementos usados pela demonstração."""

    def __init__(self, html):
        super().__init__()
        self.csrf = None
        self.links = {}
        self.rows = []
        self.href = None
        self.row = None
        self.cell = None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'input' and attrs.get('name') == 'csrf' and self.csrf is None:
            self.csrf = attrs.get('value')
        if tag == 'a':
            self.href = attrs.get('href')
        if tag == 'tr':
            self.row = []
        if tag == 'td' and self.row is not None:
            self.cell = []

    def handle_data(self, data):
        if self.href:
            self.links[self.href] = self.links.get(self.href, '') + data
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag == 'a':
            self.href = None
        if tag == 'td' and self.cell is not None:
            self.row.append(''.join(self.cell).strip())
            self.cell = None
        if tag == 'tr' and self.row is not None:
            if len(self.row) == 4:
                self.rows.append(tuple(self.row))
            self.row = None


@dataclass(frozen=True)
class Response:
    status: int
    body: str | bytes
    headers: object


def lab_address():
    url = os.environ.get('BASE_URL', 'https://localhost:8443').rstrip('/')
    address = urlsplit(url)
    host = address.hostname
    port = address.port or 443
    if (address.scheme != 'https' or address.username is not None or address.password is not None
            or address.path or address.query or address.fragment or not 1024 <= port <= 65535):
        raise ValueError('Use a URL HTTPS do laboratório, com porta explícita e sem caminho.')
    if host == 'server' and port == 8443 and Path('/.dockerenv').is_file():
        return url, host, port
    if host in ('localhost', '127.0.0.1', '::1'):
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if addresses and all(ip_address(entry[4][0]).is_loopback for entry in addresses):
            return url, host, port
    raise ValueError('Use https://server:8443 no Docker ou um endereço loopback no host.')


def opener(context):
    return build_opener(
        ProxyHandler({}), HTTPCookieProcessor(http.cookiejar.CookieJar()),
        HTTPSHandler(context=context), NoRedirect(),
    )


def request(op, url, route, payload=None, *, binary=False, content_type='application/x-www-form-urlencoded'):
    headers = {}
    data = None
    if payload is not None:
        data = payload if isinstance(payload, bytes) else urlencode(payload).encode('utf-8')
        headers['Content-Type'] = content_type
    try:
        response = op.open(Request(url + route, data=data, headers=headers), timeout=TIMEOUT)
    except HTTPError as error:
        response = error
    with response:
        body = response.read()
        return Response(response.code, body if binary else body.decode('utf-8'), response.headers)


def upload(op, url, filename, data, token):
    boundary = f'portal-teste-{secrets.token_hex(12)}'
    separator = f'--{boundary}'.encode('ascii')
    parts = []
    if token is not None:
        parts.extend((separator, b'Content-Disposition: form-data; name="csrf"', b'', token.encode('ascii')))
    if filename is not None:
        disposition = f'Content-Disposition: form-data; name="file"; filename="{filename}"'.encode('utf-8')
        parts.extend((separator, disposition, b'Content-Type: application/octet-stream', b'', data))
    parts.extend((separator + b'--', b''))
    return request(op, url, '/files', b'\r\n'.join(parts), content_type=f'multipart/form-data; boundary={boundary}')


def login(op, url, username, password):
    form = request(op, url, '/login')
    csrf = PortalHTML(form.body).csrf
    if form.status != 200 or not csrf:
        raise ValueError('Formulário de login indisponível ou sem token CSRF.')
    return request(op, url, '/login', {'username': username, 'password': password, 'csrf': csrf})


def rejected_tls(host, port, context, server_name):
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=server_name):
                return False
    except ssl.SSLCertVerificationError:
        return True


def event_rows(response):
    return Counter(PortalHTML(response.body).rows) if response.status == 200 else Counter()


def recent_event(before, after, code):
    return any(
        row[2] == code and re.fullmatch(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC', row[0])
        for row in after - before
    )


class Report:
    def __init__(self):
        self.results = {}

    def check(self, case, label, ok, evidence=None):
        self.results[case] = bool(ok)
        status = 'PASSOU' if ok else 'FALHOU'
        detail = f' | {evidence}' if evidence else ''
        print(f'{status:7} | T{case:02} | {label}{detail}', flush=True)

    def finish(self):
        missing = set(HTTP_CASES) - self.results.keys()
        for case in sorted(missing):
            print(f'PENDENTE | T{case:02} | Verificação não executada.')
        passed = sum(self.results.values())
        failed = len(self.results) - passed
        print(f'HTTPS: {passed}/{len(HTTP_CASES)} passaram, {failed} falharam, {len(missing)} pendentes.')
        print('T08, T10, T23 e T24 são executados pelo auditor do SQLite no servidor.')
        return int(bool(failed or missing))


def exercise_attachment(report, url, guest, student, admin, colleague, token, run_id):
    filename, data = sample_attachment(run_id)
    before = event_rows(request(admin, url, '/admin/logs'))
    uploaded = upload(student, url, filename, data, token)
    listing = PortalHTML(request(student, url, '/notes').body)
    route = next((link for link, label in listing.links.items()
                  if label.strip() == filename and re.fullmatch(r'/files/download\?id=\d+', link)), None)
    report.check(16, 'PDF fictício enviado e localizado na lista de documentos',
                 uploaded.status == 303 and route is not None,
                 f'cadastro HTTP {uploaded.status} | arquivo listado: {route is not None}')
    file_id = None
    if route is not None:
        file_id = route.partition('=')[2]
        downloaded = request(student, url, route, binary=True)
        disposition = downloaded.headers.get('Content-Disposition', '')
        extended_name = re.search(r"(?:^|;\s*)filename\*=UTF-8''([^;]+)", disposition, re.IGNORECASE)
        matching_name = extended_name is not None and unquote(extended_name[1], errors='strict') == filename
        report.check(17, 'Proprietário baixa os mesmos bytes como anexo',
                     downloaded.status == 200 and downloaded.body == data and matching_name
                     and downloaded.headers.get_content_type() == 'application/pdf'
                     and disposition.lower().startswith('attachment;')
                     and downloaded.headers.get('X-Content-Type-Options', '').lower() == 'nosniff',
                     f'HTTP {downloaded.status} | bytes idênticos: {downloaded.body == data} '
                     f'| nome original: {matching_name}')
        colleague_download = request(colleague, url, route, binary=True)
        admin_download = request(admin, url, route, binary=True)
        colleague_listing = request(colleague, url, '/notes')
        private_values = (filename.encode('utf-8'), attachment_marker(run_id).encode('ascii'))
        report.check(18, 'URL direta nega download ao colega e ao administrador',
                     colleague_download.status == admin_download.status == 403
                     and colleague_listing.status == 200 and filename not in colleague_listing.body
                     and all(value not in answer.body for answer in (colleague_download, admin_download)
                             for value in private_values),
                     f'HTTP {colleague_download.status}/{admin_download.status}')
        guest_download = request(guest, url, route, binary=True)
        report.check(19, 'URL direta exige sessão para baixar o arquivo',
                     guest_download.status == 302 and guest_download.headers.get('Location') == '/login'
                     and data not in guest_download.body, f'HTTP {guest_download.status}')
    else:
        report.check(17, 'Proprietário baixa os mesmos bytes como anexo', False, 'PDF sem ID para download.')
        report.check(18, 'URL direta nega download ao colega e ao administrador', False, 'PDF sem ID para download.')
        report.check(19, 'URL direta exige sessão para baixar o arquivo', False, 'PDF sem ID para download.')

    invalid = {
        'sem arquivo': upload(student, url, None, None, token).status,
        'vazio': upload(student, url, 'vazio.txt', b'', token).status,
        'extensão': upload(student, url, 'imagem.png', b'Conteudo ficticio', token).status,
        'formato': upload(student, url, 'texto.pdf', b'Conteudo ficticio', token).status,
        'multipart': request(student, url, '/files', b'formulario incompleto',
                             content_type='multipart/form-data; boundary=teste').status,
    }
    too_large = upload(student, url, 'grande.txt', b'a' * (2 * 1024 * 1024 + 1), token).status
    wrong_mime = request(student, url, '/files', {'csrf': token}).status
    report.check(20, 'Upload rejeita entradas inválidas e aplica limite de 2 MiB',
                 all(status == 400 for status in invalid.values()) and too_large == 413 and wrong_mime == 415,
                 ', '.join(f'{label} HTTP {status}' for label, status in invalid.items())
                 + f', tamanho HTTP {too_large}, formulário HTTP {wrong_mime}')
    csrf_codes = [upload(student, url, filename, data, value).status for value in (None, 'token-invalido')]
    report.check(21, 'Upload rejeita token CSRF ausente e inválido',
                 csrf_codes == [403, 403], f'HTTP {csrf_codes[0]}/{csrf_codes[1]}')

    logged = request(admin, url, '/admin/logs')
    after = event_rows(logged)
    log_text = ' '.join(' '.join(row) for row in after)
    report.check(22, 'Envio, download e recusa são registrados sem nome ou conteúdo',
                 logged.status == 200 and all(recent_event(before, after, code) for code in
                                             ('ARQUIVO_ENVIADO', 'ARQUIVO_BAIXADO', 'ACESSO_NEGADO'))
                 and not any(value in log_text for value in (filename, attachment_marker(run_id), token)),
                 f'HTTP {logged.status}')
    return file_id


def exercise(report):
    url, host, port = lab_address()
    cert = os.environ.get('CA_CERT', 'tls/server.crt')
    context = ssl.create_default_context(cafile=cert)
    admin_password = os.environ['DEMO_ADMIN_PASSWORD']
    user_password = os.environ['DEMO_USER_PASSWORD']
    other_password = os.environ['DEMO_OTHER_PASSWORD']
    guest, student, admin, colleague, test_account = (opener(context) for _ in range(5))

    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=host) as secure:
            version = secure.version()
            local_ip = secure.getsockname()[0]
            remote_ip = secure.getpeername()[0]
    health = request(guest, url, '/health')
    untrusted = rejected_tls(host, port, ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), host)
    wrong_name = rejected_tls(host, port, context, 'nome-incorreto.invalid')
    report.check(1, 'HTTPS com certificado validado',
                 version in ('TLSv1.2', 'TLSv1.3') and health.status == 200
                 and health.body == 'OK' and untrusted and wrong_name,
                 f'{version} | origem {local_ip} | destino {remote_ip}:{port} | HTTP {health.status} '
                 f'| certificado sem confiança rejeitado: {untrusted} | nome incorreto rejeitado: {wrong_name}')

    guest_list = request(guest, url, '/notes')
    guest_doc = request(guest, url, '/notes/view?id=1')
    report.check(2, 'Área de documentos e leitura exigem login',
                 all(item.status == 302 and item.headers.get('Location') == '/login'
                     for item in (guest_list, guest_doc)), f'HTTP {guest_list.status}/{guest_doc.status}')

    signed_in = login(student, url, 'aluno', user_password)
    notes = request(student, url, '/notes')
    cookie = signed_in.headers.get('Set-Cookie', '').lower().split(';')
    attributes = {part.strip() for part in cookie[1:]}
    report.check(3, 'Credencial correta cria sessão com cookie protegido',
                 signed_in.status == 303 and notes.status == 200
                 and {'secure', 'httponly', 'samesite=lax'} <= attributes,
                 f'HTTP {signed_in.status}/{notes.status}')

    wrong = login(test_account, url, 'aluno', INVALID_PASSWORD)
    after_wrong = request(test_account, url, '/notes')
    report.check(4, 'Senha incorreta não inicia sessão', wrong.status == 401 and after_wrong.status == 302,
                 f'HTTP {wrong.status}/{after_wrong.status}')

    denied_admin = request(student, url, '/admin/logs')
    report.check(5, 'Usuário comum não acessa logs administrativos',
                 denied_admin.status == 403, f'HTTP {denied_admin.status}')

    admin_login = login(admin, url, 'admin', admin_password)
    admin_view = request(admin, url, '/admin/logs')
    report.check(6, 'Administrador autenticado consulta os logs',
                 admin_login.status == 303 and admin_view.status == 200 and 'Logs de segurança' in admin_view.body,
                 f'HTTP {admin_login.status}/{admin_view.status}')

    # O identificador não é segredo. Correlaciona este cadastro com o auditor no servidor.
    run_id = secrets.token_hex(8)
    title = f'Documento fictício de teste {run_id}'
    content = f'CONTEUDO_FICTICIO_RA2_{run_id}'
    token = PortalHTML(notes.body).csrf
    if not token:
        raise ValueError('Formulário de documentos indisponível ou sem token CSRF.')
    created = request(student, url, '/notes', {'csrf': token, 'title': title, 'body': content})
    listing = PortalHTML(request(student, url, '/notes').body)
    doc_id = next((route.split('=', 1)[1] for route, label in listing.links.items()
                   if label.strip() == title and re.fullmatch(r'/notes/view\?id=\d+', route)), None)
    colleague_login = login(colleague, url, 'colega', other_password)
    if created.status == 303 and doc_id is not None:
        route = f'/notes/view?id={doc_id}'
        colleague_view = request(colleague, url, route)
        colleague_list = request(colleague, url, '/notes')
        report.check(7, 'Documento fica restrito ao proprietário',
                     colleague_login.status == 303 and colleague_view.status == 403 and colleague_list.status == 200
                     and title not in colleague_list.body and content not in colleague_view.body,
                     f'HTTP {colleague_view.status}')
        owner_view = request(student, url, route)
        report.check(9, 'Proprietário abre o mesmo documento criado',
                     owner_view.status == 200 and title in owner_view.body and content in owner_view.body,
                     f'cadastro HTTP {created.status}, leitura HTTP {owner_view.status}')
    else:
        report.check(9, 'Proprietário abre o mesmo documento criado', False, f'cadastro HTTP {created.status}')

    form = {'title': 'Documento de teste de formulário', 'body': 'Conteúdo fictício'}
    missing_csrf = request(student, url, '/notes', form)
    invalid_csrf = request(student, url, '/notes', {**form, 'csrf': 'token-invalido'})
    report.check(11, 'Servidor rejeita token CSRF ausente e inválido',
                 missing_csrf.status == invalid_csrf.status == 403,
                 f'HTTP {missing_csrf.status}/{invalid_csrf.status}')

    before = event_rows(request(admin, url, '/admin/logs'))
    codes = [login(test_account, url, 'aluno', INVALID_PASSWORD).status for _ in range(3)]
    detected = event_rows(request(admin, url, '/admin/logs'))
    report.check(12, 'Três falhas em conta fictícia acionam a detecção',
                 codes == [401, 401, 401] and recent_event(before, detected, 'DETECCAO_FORCA_BRUTA'),
                 f'HTTP {codes}')

    blocked = login(test_account, url, 'aluno', user_password)
    retry_value = blocked.headers.get('Retry-After', '')
    delay = int(retry_value) if re.fullmatch(r'\d{1,2}', retry_value) else 0
    resumed_status = None
    if blocked.status == 429 and 1 <= delay <= 60:
        print(f'T13 em andamento. Aguardando {delay} s pelo fim do bloqueio.', flush=True)
        time.sleep(delay + 0.25)
        resumed_status = login(test_account, url, 'aluno', user_password).status
    report.check(13, 'Bloqueio rejeita login válido e expira', blocked.status == 429 and resumed_status == 303,
                 f'HTTP {blocked.status} | espera informada {delay} s | após espera: {resumed_status}')

    logged = request(admin, url, '/admin/logs')
    logged_rows = event_rows(logged)
    protected_values = (admin_password, user_password, other_password, INVALID_PASSWORD, token, title, content)
    log_text = ' '.join(' '.join(row) for row in logged_rows)
    report.check(14, 'Registro administrativo de detecção e bloqueio, com data UTC',
                 logged.status == 200 and recent_event(before, logged_rows, 'DETECCAO_FORCA_BRUTA')
                 and recent_event(before, logged_rows, 'LOGIN_BLOQUEADO')
                 and all(value not in log_text for value in protected_values), f'HTTP {logged.status}')

    invalid_form = request(student, url, '/notes', {**form, 'csrf': token, 'title': ''})
    invalid_id = request(student, url, '/notes/view?id=0')
    recovered = request(student, url, '/notes')
    report.check(15, 'Entradas inválidas retornam erro e a aplicação segue disponível',
                 invalid_form.status == invalid_id.status == 400 and recovered.status == 200,
                 f'HTTP {invalid_form.status}/{invalid_id.status}/{recovered.status}')

    file_id = exercise_attachment(report, url, guest, student, admin, colleague, token, run_id)
    if created.status == 303 and doc_id is not None:
        print(f'ID de evidência: {doc_id} | Execução: {run_id}')
        file_option = f' --file-id {file_id}' if file_id is not None else ''
        print('Comando da auditoria em PowerShell: '
              f'docker compose exec -T server python audit_storage.py --id {doc_id} --run-id {run_id}{file_option}',
              flush=True)


def main():
    report = Report()
    try:
        exercise(report)
    except KeyError:
        print('Configuração incompleta. Defina as três variáveis DEMO_*_PASSWORD do laboratório.')
    except ssl.SSLCertVerificationError:
        report.check(1, 'A validação do certificado TLS do laboratório falhou', False)
    except (URLError, OSError, ValueError) as error:
        # O tipo basta para diagnosticar conexão, timeout, certificado ausente ou URL inválida.
        print(f'Execução interrompida ({type(error).__name__}). Confira a URL, o formulário e o certificado do laboratório.')
    return report.finish()


if __name__ == '__main__':
    raise SystemExit(main())
