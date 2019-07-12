import mysql.connector
import pgpy, uuid
import cryptic

def connect():
    db = mysql.connector.connect(
      host="localhost",
      user="",
      password=""
      database="CodeTunnel"
    )
    return db

def requestData(db, table, key, value, many=False, dump=False):
    cursor = db.cursor(dictionary=True)
    sql = "SELECT * FROM " + table
    cursor.execute(sql)
    result = cursor.fetchall()
    resp = []
    for asset in result:
        if (key in asset and asset[key] == value) or dump:
            if many == False: return asset
            resp.append(asset)
    if len(resp)!= 0 or many: return resp
    else: return False

def whereData(db, table, key, value):
    cursor = db.cursor(dictionary=True)
    sql = "SELECT * FROM " + table + " WHERE " + key + " = %s"
    cursor.execute(sql, (value,))
    result = cursor.fetchall()
    return result

def createNode(keystr, force=False):
    db = connect()
    output = {"success": False}
    if (len(str(keystr)) >= 4096):
        output["error"] = "keyExceedsLength"
        return output
    key = cryptic.keyInfo(keystr)
    if not key["success"]:
        output["error"] = key["error"]
        return output
    id = str(uuid.UUID(key["data"]["NODE"])).upper()
    if requestData(db, "Nodes", "NodeID", id):
        if not force:
            output["error"] = "nodeExists"
            return output
        else:
            if not deleteNode(id)["success"]:
                output["error"] = deleteNode(id)["error"]
                return output
            else:
                key = cryptic.keyInfo(keystr)
    if not key["verified"]:
        output["error"] = "keyVerificationFailed"
        return output
    cursor = db.cursor()
    sql = "INSERT INTO Nodes (NodeID, Type, FriendlyName, PublicKey) VALUES (%s, %s, %s, %s)"
    pubkey = key["public"]
    if key["type"] == "XPDR" and "private" in key:
        pubkey = key["private"]
    if (len(str(pubkey)) >= 4096):
        output["error"] = "keyExceedsLength"
        return output
    cursor.execute(sql, (str(id), str(key["type"]), str(key["name"]), str(pubkey)))
    db.commit()

    output["delta"] = cursor.rowcount
    output["UUID"] = str(id)
    output["success"] = True
    return output

def createMessage(source, destination, message):
    message = str(message)
    output = {"success": False}
    if (len(str(message)) >= 4096):
        output["error"] = "messageExceedsLength"
        return output
    if not getNode(source):
        output["error"] = "invalidSourceNode"
        return output
    else:
        source = getNode(source)["NodeID"]
    if not getNode(destination):
        output["error"] = "invalidDestinationNode"
        return output
    else:
        destination = getNode(destination)["NodeID"]
    try:
        if not (pgpy.PGPMessage.from_blob(message).is_encrypted):
            output["error"] = "messageNotEncrypted"
            return output
    except:
        output["error"] = "invalidMessage"
        return output
    output["MessageID"] = str(uuid.uuid4()).upper()
    db = connect()
    cursor = db.cursor()
    sql = "INSERT INTO Messages (MessageID, Source, Destination, Message) VALUES (%s, %s, %s, %s)"
    cursor.execute(sql, (str(output["MessageID"]), str(source), str(destination), str(message)))
    db.commit()
    output["delta"] = cursor.rowcount
    output["success"] = True
    return output

def deleteNode(ident):
    id = None
    output = {"success": False}
    if type(ident) == str:
        if len(str(ident)) == 36:
            id = str(uuid.UUID(ident)).upper()
    if (id == None):
        k = cryptic.isKey(ident)
        if not k:
            output["error"] = "badIdentifier"
            return output
        v = cryptic.keyInfo(k)
        if v["success"]:
            id = str(uuid.UUID(v["data"]["NODE"])).upper()
        else:
            output["error"] = "badKey"
    output["UUID"] = id
    sql = "DELETE FROM Nodes WHERE NodeID = %s"
    db = connect()
    cursor = db.cursor()
    cursor.execute(sql, (id,))
    delta = cursor.rowcount
    if not (delta == 1):
        output["error"] = "incorrectCasualties"
        db.rollback()
        return output
    db.commit()
    output["delta"] = cursor.rowcount
    output["success"] = True
    return output

def deleteMessages(destination):
    id = None
    output = {"success": False}
    id = str(uuid.UUID(destination)).upper()
    sql = "DELETE FROM Messages WHERE Destination = %s"
    db = connect()
    cursor = db.cursor()
    cursor.execute(sql, (id,))
    db.commit()
    output["delta"] = cursor.rowcount
    output["success"] = True
    return output

def getNode(ident, sensitive=False):
    if (cryptic.isKey(ident)):
        return cryptic.isKey(ident)
    try:
        id = str(uuid.UUID(ident)).upper()
    except:
        return False
    db = connect()
    res = whereData(db, "Nodes", "NodeID", str(id))
    if len(res) != 1:
        return False
    res = res[0]
    if (not sensitive):
        if "BEGIN PGP PRIVATE KEY BLOCK" in res["PublicKey"]:
            res["PublicKey"] = str(cryptic.keyInfo(res["PublicKey"])["public"])
    return res
