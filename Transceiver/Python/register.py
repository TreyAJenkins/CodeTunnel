#!/usr/bin/env python

#1) Allow clients to request a new and random UUID without collision
#2) Allow clients to upload their public key


debug = False

import cgitb, cgi
if debug:
	cgitb.enable()
	print "Content-Type: text/html\r\n\r\n"
else:
    print "Content-Type: application/json\r\n\r\n"

import time
start = time.time()
import json, uuid
import database

with open('config.json', 'r') as configfile:
    config = json.load(configfile)

form = cgi.FieldStorage()
action = str(form.getvalue("action")).upper() # Either GENERATE or UPLOAD
output = {"success": False, "XPDR": config["XPDR"]}

def finish():
    output["ExecutionTime"] = round(time.time() - start, 3)
    print json.dumps(output)
    exit(0)

def validUUID(uuid_string):
    try:
        val = uuid.UUID(uuid_string, version=4)
        return True
    except ValueError:
        return False

def generateUUID():
    db = database.connect()
    while True:
        candidate = str(uuid.uuid4()).upper()
        if not database.requestData(db, "Nodes", "NodeID", candidate): return candidate

if action == "GENERATE":
    try:
        output["UUID"] = generateUUID()
        output["success"] = True
    except:
        output["error"] = "generateUUID/exception"
elif action == "UPLOAD":
    key = str(form.getvalue("key"))
    resp = database.createNode(key)
    output["success"] = resp["success"]
    if "error" in resp:
        output["error"] = resp["error"]

finish()
