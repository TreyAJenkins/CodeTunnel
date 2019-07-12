#!/usr/bin/env python

#1) Allow clients to request their messages
#2) Allow clients to upload their messages


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
data = str(form.getvalue("data"))
output = {}
source = None
destination = None


def finish():
    output["ExecutionTime"] = round(time.time() - start, 3)
    print json.dumps(output)
    exit(0)

def unpack(data, sender):
    result = cryptic.decrypt(data, sender, str(config["XPDR"]["UUID"]).upper())
    if result["success"]:
        return result["message"]
    else:
        output["success"] = False
        output["error"] = result["error"]
        finish()

try:
    data = json.loads(data)
    source = data["source"]
    destination = data["destination"]
    data = data["data"]
except:
    output["error"] = "malformedData"
    output["input"] = data
    output["success"] = False
    finish()

data = unpack(data, source)
try:
    mx = json.loads(data)
    if mx["method"] == "download":
        output["download"] = database.whereData(database.connect(), "Messages", "Destination", source)
        database.deleteMessages(source)
except:
    output = database.createMessage(source, destination, data)


finish()
