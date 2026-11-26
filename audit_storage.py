"""Audita no servidor as notas e os anexos fictícios criados pelo cliente de testes."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import re
import sqlite3

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from file_test_fixture import attachment_marker, sample_attachment


def has_plaintext(path, markers):
    """Procura os marcadores de teste sem imprimir o conteúdo do arquivo."""
    carry = b''
    carry_size = max(map(len, markers)) - 1
    with path.open('rb') as stream:
        while chunk := stream.read(65536):
            window = carry + chunk
            if any(marker in window for marker in markers):
                return True
            carry = window[-carry_size:]
    return False


def read_document(path, note_id):
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)) as database:
        return database.execute(
            'SELECT n.owner_id, n.nonce, n.ciphertext FROM notes n '
            'JOIN users u ON u.id = n.owner_id WHERE n.id = ? AND u.username = ?',
            (note_id, 'aluno'),
        ).fetchone()


def read_attachment(path, file_id):
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)) as database:
        return database.execute(
            'SELECT f.owner_id, f.nonce, f.ciphertext, f.name_nonce, f.encrypted_name FROM files f '
            'JOIN users u ON u.id = f.owner_id WHERE f.id = ? AND u.username = ?',
            (file_id, 'aluno'),
        ).fetchone()


def check_aes256(key_path, row, expected):
    owner_id, nonce, ciphertext = row
    key = key_path.read_bytes()
    if len(key) != 32 or not isinstance(nonce, bytes) or not isinstance(ciphertext, bytes):
        return False
    if len(nonce) != 12 or len(ciphertext) <= 16:
        return False
    try:
        data = AESGCM(key).decrypt(nonce, ciphertext, f'usuario:{owner_id}'.encode())
        return json.loads(data) == expected
    except (InvalidTag, UnicodeError, ValueError):
        return False


def check_attachment_aes256(key_path, row, filename, contents):
    owner_id, nonce, ciphertext, name_nonce, encrypted_name = row
    key = key_path.read_bytes()
    if len(key) != 32 or not all(isinstance(value, bytes) for value in row[1:]):
        return False
    if len(nonce) != 12 or len(name_nonce) != 12 or nonce == name_nonce:
        return False

    aes = AESGCM(key)
    try:
        decrypted = aes.decrypt(nonce, ciphertext, f'portal-file-v1:conteudo:{owner_id}'.encode('ascii'))
        name_data = f'portal-file-v1:nome:{owner_id}'.encode('ascii') + nonce
        name = aes.decrypt(name_nonce, encrypted_name, name_data)
        return decrypted == contents and name == filename.encode('utf-8')
    except (InvalidTag, ValueError):
        return False


def inspect_plaintext(path, markers):
    files = [path]
    files.extend(sidecar for suffix in ('-wal', '-journal')
                 if (sidecar := path.with_name(path.name + suffix)).is_file())
    return any(has_plaintext(file, markers) for file in files), ', '.join(file.name for file in files)


def inspect(note_id, run_id):
    data_dir = Path(os.environ.get('DATA_DIR', 'data'))
    key_path = Path(os.environ.get('KEY_DIR', data_dir)) / 'aes.key'
    path = data_dir / 'portal.db'
    expected = {'title': f'Documento fictício de teste {run_id}', 'body': f'CONTEUDO_FICTICIO_RA2_{run_id}'}
    print(f'ID de evidência: {note_id} | Execução: {run_id}')
    row = read_document(path, note_id)
    if row is None:
        print('FALHOU  | T08 | Documento indicado não está registrado para a conta de teste.')
        print('PENDENTE | T10 | Selecione o ID impresso na execução do cliente.')
        return 1

    valid = check_aes256(key_path, row, expected)
    encrypted = 'PASSOU' if valid else 'FALHOU'
    print(f'{encrypted:7} | T08 | AES-256-GCM autenticado para o documento identificado: {valid}.')
    if valid:
        print(f'Nonce: {len(row[1])} bytes | Cifra com tag: {len(row[2])} bytes.')
    else:
        print('PENDENTE | T10 | A auditoria exige que T08 confirme o documento e a execução.')
        return 1

    markers = tuple(text.encode(encoding) for text in (*expected.values(), run_id)
                    for encoding in ('utf-8', 'utf-16-le', 'utf-16-be'))
    plaintext, files = inspect_plaintext(path, markers)
    status = 'FALHOU' if plaintext else 'PASSOU'
    state = 'encontrados' if plaintext else 'ausentes'
    print(f'{status:7} | T10 | Marcadores fictícios {state} em {files}.')
    return int(plaintext)


def inspect_attachment(file_id, run_id):
    data_dir = Path(os.environ.get('DATA_DIR', 'data'))
    key_path = Path(os.environ.get('KEY_DIR', data_dir)) / 'aes.key'
    path = data_dir / 'portal.db'
    filename, contents = sample_attachment(run_id)
    row = read_attachment(path, file_id)
    print(f'ID de evidência do arquivo: {file_id} | Execução: {run_id}')
    valid = row is not None and check_attachment_aes256(key_path, row, filename, contents)
    status = 'PASSOU' if valid else 'FALHOU'
    print(f'{status:7} | T23 | AES-256-GCM autenticou e recuperou os bytes e o nome originais: {valid}.')
    if not valid:
        print('PENDENTE | T24 | Confirme o ID e a execução do anexo no teste T23.')
        return 1

    print(f'Nonces: {len(row[1])}/{len(row[3])} bytes | Cifras com tags: {len(row[2])}/{len(row[4])} bytes.')
    markers = (contents, *(text.encode(encoding) for text in (filename, attachment_marker(run_id))
                           for encoding in ('utf-8', 'utf-16-le', 'utf-16-be')))
    plaintext, files = inspect_plaintext(path, markers)
    status = 'FALHOU' if plaintext else 'PASSOU'
    state = 'encontrados' if plaintext else 'ausentes'
    print(f'{status:7} | T24 | Bytes, nome e marcador fictícios {state} em {files}.')
    return int(plaintext)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--id', required=True, type=int, help='ID informado pelo cliente de testes')
    parser.add_argument('--run-id', required=True, help='Identificador hexadecimal informado pelo cliente')
    parser.add_argument('--file-id', type=int, help='ID do anexo informado pelo cliente de testes')
    args = parser.parse_args()
    ids = (args.id,) if args.file_id is None else (args.id, args.file_id)
    if not all(1 <= record_id <= 2**63 - 1 for record_id in ids) or not re.fullmatch(r'[0-9a-f]{16}', args.run_id):
        parser.error('Informe o ID e o identificador de execução emitidos pelo cliente de testes.')
    try:
        note_result = inspect(args.id, args.run_id)
        if args.file_id is None:
            return note_result
        file_result = inspect_attachment(args.file_id, args.run_id)
        return max(note_result, file_result)
    except (OSError, sqlite3.Error) as error:
        print(f'Auditoria incompleta ({type(error).__name__}). Confira o diretório do banco e a chave local.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
