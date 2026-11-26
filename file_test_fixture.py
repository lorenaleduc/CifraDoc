"""Arquivo PDF fictício, reproduzível, para os testes e a auditoria do portal."""


def attachment_marker(run_id):
    return f'ANEXO_FICTICIO_RA2_{run_id}'


def sample_attachment(run_id):
    filename = f'Anexo fictício {run_id}.pdf'
    page = f'BT /F1 12 Tf 72 720 Td ({attachment_marker(run_id)}) Tj ET'.encode('ascii')
    objects = (
        b'<< /Type /Catalog /Pages 2 0 R >>',
        b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] '
        b'/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
        b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
        f'<< /Length {len(page)} >>\nstream\n'.encode('ascii') + page + b'\nendstream',
    )
    document = bytearray(b'%PDF-1.4\n')
    offsets = []
    for index, value in enumerate(objects, start=1):
        offsets.append(len(document))
        document.extend(f'{index} 0 obj\n'.encode('ascii') + value + b'\nendobj\n')

    xref = len(document)
    document.extend(f'xref\n0 {len(objects) + 1}\n0000000000 65535 f \n'.encode('ascii'))
    for offset in offsets:
        document.extend(f'{offset:010} 00000 n \n'.encode('ascii'))
    document.extend(
        f'trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode('ascii')
    )
    return filename, bytes(document)
