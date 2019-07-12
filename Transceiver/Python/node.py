#!/usr/bin/env python

#1) Allow clients to request a copy of a node's public key

debug = False

import cgitb, cgi
if debug:
	cgitb.enable()
	print "Content-Type: text/html\r\n\r\n"
else:
    print "Content-Type: application/json\r\n\r\n"

import time
start = time.time()
import json
import database, cryptic

with open('config.json', 'r') as configfile:
    config = json.load(configfile)

form = cgi.FieldStorage()
uuids = str(form.getvalue("get")).upper() # UUID of node to get
id = str(form.getvalue("uuid")).upper() # UUID of requesting node

output = {}

def finish():
    output["ExecutionTime"] = round(time.time() - start, 3)
    print json.dumps(output)
    exit(0)

nodes = {}
for x in uuids.split(","):
    if "XPDR" in x.upper() or x.upper() == "NONE":
        nodes["XPDR"] = database.getNode(str(config["XPDR"]["UUID"]).upper())
    else:
        nodes[x] = database.getNode(x.upper())
output["node"] = nodes

if id != "NONE":
    output["security"] = {"success": False}
    output["security"] = cryptic.encrypt(json.dumps(output["node"]), str(config["XPDR"]["UUID"]).upper(), id)
    if output["security"]["success"]:
        del output["node"]
        output["security"]["source"] = str(config["XPDR"]["UUID"]).upper()
        output["security"]["destination"] = str(id).upper()

finish()
