#!/bin/env python3

from ownca import CertificateAuthority
import string
import random
import uuid
import datetime
import sqlite3
import arrow
from fastapi import FastAPI
from fastapi import Request
import uvicorn
#from contextlib import asynccontextmanager
from pydantic import BaseModel

#@asynccontextmanager
#async def lifespan(app: FastAPI):
#    # Load the ML model
#    db = sqlite3.connect("/tmp/csc.db")
#    cur = db.cursor()
#    try:
#        cur.execute("CREATE TABLE request(passkey, timestamp)")
#        db.commit()
#    except Exception as e:
#        print(e)
#        #db.create_table("request", {'passkey': str, 'timestamp': str})
#    yield

app = FastAPI()

basedir ="/tmp/csc"

def store_passkey(passkey):
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    #db.append("request", {"passkey": passkey, "timestamp": timestamp})
    db = sqlite3.connect("/tmp/csc.db")
    try:
        cur = db.cursor()
        cur.execute("CREATE TABLE request(passkey, timestamp)")
        db.commit()
    except Exception as e:
        print(e)
    cur = db.cursor()
    data = (passkey, timestamp)
    cur.execute("""
    INSERT INTO request VALUES
        (?, ?)
    """, data)
    db.commit()

@app.get("/db")
def list_db(request: Request):
    #return db.pull('request')
    db = sqlite3.connect("/tmp/csc.db")
    cur = db.cursor()
    res = cur.execute("""
    SELECT * FROM request
    """)
    response = res.fetchall()
    return response

@app.get("/app")
def read_main(request: Request):
    return {"message": "Hello World", "root_path": request.scope.get("root_path")}

@app.get("/csc/register")
def csc(request: Request):
    passkey = get_random_string(20)
    store_passkey(passkey)
    return {"passkey": passkey}

class Item(BaseModel):
    passkey: str
    fqdn: str

@app.post("/csc/cert")
def cert(info : Item):
    #content = await info.json()
    content = info
    print(content)
    passkey = content.passkey
    fqdn = content.fqdn
    #response = db.pull_where('request', f'passkey = "{ passkey }"')
    db = sqlite3.connect("/tmp/csc.db")
    cur = db.cursor()
    data = (passkey,)
    res = cur.execute("""
    SELECT * FROM request WHERE passkey = ?
    """, data)
    response = res.fetchone() 
    print(response)
    if len(response) > 0:
        timestamp = response[1]
        now = arrow.utcnow()
        print(now.shift(minutes=-5))
        print(arrow.get(timestamp))
        if now.shift(minutes=-5) < arrow.get(timestamp):
            certs = create_cert(fqdn) 
            print(certs)
            #with db as cursor:
            #    sql = 'DELETE FROM REQUEST WHERE PASSKEY=?'
            #    cursor.execute(sql, (passkey,))
            cur = db.cursor()
            data = (passkey,)
            res = cur.execute("""
            DELETE FROM request where passkey=?
            """, data)
            db.commit()
            return certs
        else:
            return {"error": "passkey expired"}
    else:
        return {"error": "passkey does not exist"}

def create_cert(fqdn):
    ca = CertificateAuthority(ca_storage='/tmp/CA', common_name='dog CA')

    server = ca.issue_certificate(fqdn, dns_names=[fqdn, 'localhost'])
    hostkey = str(uuid.uuid1())

    return {"server_key": server.key_bytes.decode("utf-8"),
            "server_crt": server.cert_bytes.decode("utf-8"), 
            "ca_crt": ca.cert_bytes.decode("utf-8"),
            "hostkey": hostkey}

def get_random_string(length):
    # choose from all lowercase letter
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def lambda_handler(event, context):
    fqdn = event["fqdn"]
    certs = create_cert(fqdn)
    return certs

def main(argv, stdout, environ):
    fqdn=argv[1]
    event = {"fqdn": fqdn}
    response_map = lambda_handler(event,[])
    print(f"server_key: {response_map['server_key']}")
    print(f"server_key: {response_map['server_key']}")
    print(f"server_crt: {response_map['server_crt']}")

if __name__ == "__main__":
    uvicorn.run("main:app",port=8000,reload=True)
