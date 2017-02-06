#!/usr/bin/env python3
import base64
import pyshark
import struct
import subprocess

domain = 'eat-sleep-pwn-repeat.de'
file_start_pattern = b"START_OF_FILE"
file_end_pattern = b"END_OF_FILE"
pgp_public_start_pattern = b"-----BEGIN PGP PUBLIC KEY BLOCK-----"
pgp_public_end_pattern = b"-----END PGP PUBLIC KEY BLOCK-----"
pgp_private_start_pattern = b"-----BEGIN PGP PRIVATE KEY BLOCK-----"
pgp_private_end_pattern = b"-----END PGP PRIVATE KEY BLOCK-----"


def decode_b32(s):
    s = s.upper()
    for i in range(10):
        try:
            return base64.b32decode(s)
        except:
            s += b'='
    raise ValueError('Invalid base32')


def parse_name(name):
    label = ''.join(name.split(".")[:-2]).encode()
    return decode_b32(label)


def extract_data(decoded_packet):
    header = decoded_packet[:6]
    conn_id, seq, ack = struct.unpack("<HHH", header)
    data = decoded_packet[6:]
    return data


if __name__ == '__main__':
    queries = []
    responses = []
    cap = pyshark.FileCapture('./dump.pcap')
    for packet in cap:
        dns_layer = packet['dns']
        if "Message is a response" in str(dns_layer):
            cname = dns_layer.cname
            c = extract_data(parse_name(cname))
            if c not in responses:
                responses.append(c)
        else:
            qname = dns_layer.qry_name
            c = extract_data(parse_name(qname))
            if c not in queries:
                queries.append(c)

    server_stdin = b''.join(queries)
    server_stdout = b''.join(responses)

    with open("stdin.bin", "wb") as file:
        file.write(server_stdin)

    with open("stdout.bin", "wb") as file:
        file.write(server_stdout)

    with open("secret.docx.gpg", "wb") as file:
        file.write(server_stdin[server_stdin.find(file_start_pattern) + len(file_start_pattern):server_stdin.find(file_end_pattern)])

    with open("pgp.public", "wb") as file:
        file.write(server_stdout[server_stdout.find(pgp_public_start_pattern):server_stdout.find(pgp_public_end_pattern) + len(pgp_public_end_pattern)])
    with open("pgp.private", "wb") as file:
        file.write(server_stdout[server_stdout.find(pgp_private_start_pattern):server_stdout.find(pgp_private_end_pattern) + len(pgp_private_end_pattern)])

    subprocess.run(["gpg", "--import", "./pgp.public"])
    subprocess.run(["gpg", "--allow-secret-key-import", "--import", "./pgp.private"])
    with open("secret.docx", "w") as out:
        subprocess.Popen(["gpg", "-d", "./secret.docx.gpg"], stdout=out)








