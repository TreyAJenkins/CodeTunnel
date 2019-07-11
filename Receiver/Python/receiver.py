import requests, json, uuid, pgpy, IPython, time
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm


with open('config.json', 'r') as configfile:
    config = json.load(configfile)

location = config["XPDR"]["LOCATION"]

def configUpdate():
    with open('config.json', 'w') as configfile:
        json.dump(config, configfile)

def genKey(name, type, id):
    id = str(uuid.UUID(id)).upper() # Verify valid UUID
    jsx = {"NODE": id, "XPDR": config["XPDR"]["UUID"]} # Where UUID: node UUID, XPDR: parent xpdr UUID,
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    uid = pgpy.PGPUID.new(name, comment=type, email=json.dumps(jsx))
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.Certify},
            hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
            ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
            compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
    return key

def loadKey(keystr):
    output = {"success": False}

    try:
        keystr = str(keystr)
    except:
        output["error"] = "invalidDataType"
        return output
    try:
        key, _ = pgpy.PGPKey.from_blob(keystr)
        output["success"] = True
        output["key"] = key
    except:
        output["error"] = "invalidKey"
        return output
    return output

def isKey(key):
    if type(key) == dict:
        if "key" in key:
            key = key["key"]
            return key
        else:
            return False
    if (type(key) == pgpy.pgp.PGPKey):
        return key
    lkey = loadKey(key)
    if lkey["success"]:
        key = lkey["key"]
        return key
    return False

def verifyKey(key, keydata):
    try:
        if key.is_expired:
            return False
        uuid.UUID(keydata["NODE"])
        uuid.UUID(keydata["XPDR"])

        return True
    except:
        return False
    return False

def keyInfo(key):
    try:
        output = {"success": True}
        key = isKey(key)
        if not key:
            output["success"] = False
            output["error"] = "invalidKey"
            return output
        if key.is_public:
            output["public"] = key
        else:
            output["private"] = key
            output["public"] = key.pubkey
        output["userid"] = key.userids[0]
        output["keyname"] = str(key.userids[0].name) + " (" + str(key.userids[0].comment) + ")"
        output["data"] = json.loads(str(key.userids[0].email))
        output["type"] = "X"
        if ("RCVR" in str(key.userids[0].comment).upper() or "RECEIVER" in str(key.userids[0].comment).upper()): output["type"] = "RCVR"
        if ("XMTR" in str(key.userids[0].comment).upper() or "TRANSMITTER" in str(key.userids[0].comment).upper()): output["type"] = "XMTR"
        if ("XPDR" in str(key.userids[0].comment).upper() or "TRANSPONDER" in str(key.userids[0].comment).upper()): output["type"] = "XPDR"
        output["verified"] = verifyKey(key, output["data"])
        if output["type"] == "X": output["verified"] = False
        output["name"] = key.userids[0].name
    except:
        output = {"success": False, "error": "keyParseFailed"}
    return output

def getNode(id):
    print "Requesting node: %s" % id
    r = requests.post(location + "/node.py", data={"get": id})
    r = r.json()
    return r["node"][id]

def encrypt(message, recipient):
    output = {"success": False, "message": ""}
    pubkey = None
    privkey = None

    rnode = getNode(recipient)
    if not rnode:
        output["error"] = "invalidRecipientNode"
        return output
    pubkey = keyInfo(rnode["PublicKey"])["public"]
    try:
        privkey = keyInfo(config["KEY"])["private"]
    except:
        output["error"] = "invalidSenderKey"
        return output
    try:
        message = pgpy.PGPMessage.new(message)
        message |= privkey.sign(message)
        message = pubkey.encrypt(message)
    except:
        output["error"] = "encryptionError"
        return output
    output["message"] = str(message)
    output["success"] = True
    return output

def decrypt(message, sender):
    output = {"success": False, "message": ""}
    pubkey = None
    privkey = None
    snode = getNode(sender)
    if not snode:
        output["error"] = "invalidSenderNode"
        return output

    pubkey = keyInfo(snode["PublicKey"])["public"]
    try:
        privkey = keyInfo(config["KEY"])["private"]
    except:
        output["error"] = "invalidRecipientKey"
        return output
    try:
        message = pgpy.PGPMessage.from_blob(message)
        if not message.is_encrypted:
            output["error"] = "notEncrypted"
            return output
        message = privkey.decrypt(message)
        if not message.is_signed:
            output["error"] = "notSigned"
            return output
        if not pubkey.verify(message):
            output["error"] = "invalidSignature"
            return output
        output["message"] = message.message
    except:
        output["error"] = "decryptionError"
        return output
    output["success"] = True
    return output

def register():
    r = requests.post(location + "/register.py", data={"action": "generate"})
    r = r.json()
    #print r
    config["XPDR"] = r["XPDR"]
    print "Connected to: " + r["XPDR"]["NAME"] + " [" + r["XPDR"]["UUID"] + "]"
    print "XPDR assigned UUID: " + r["UUID"]
    id = r["UUID"]

    key = genKey("Python XMTR", "XMTR", id)
    keystr = str(key)
    r = requests.post(location + "/register.py", data={"action": "upload", "key": keystr})
    r = r.json()
    if r["success"]:
        print "Key generation and upload successful"
        config["KEY"] = str(key)
        configUpdate()
        return True
    print "Failure"
    return False

def genMessage(message, destination):
    inner = encrypt(message, destination)
    if inner["success"]:
        print "Encrypted inner message to: %s" % destination
    else:
        print "Failed to encrypt inner message"
        return False
    inner = inner["message"]
    outer = encrypt(inner, config["XPDR"]["UUID"])
    if outer["success"]:
        print "Encrypted outer message to: %s" % config["XPDR"]["UUID"]
    else:
        print "Failed to encrypt outer message"
        return False
    outer = outer["message"]
    msg = {"source": keyInfo(config["KEY"])["data"]["NODE"], "destination": destination, "data": str(outer)}
    return msg

def uploadMessage(message):
    print "Uploading message: %s -> %s" % (message["source"], message["destination"])
    r = requests.post(location + "/message.py", data={"data": json.dumps(message)})
    return r.json()

def downloadMessages():
    msg = {"method": "download"}
    outer = encrypt(json.dumps(msg), config["XPDR"]["UUID"])
    msg = {"source": keyInfo(config["KEY"])["data"]["NODE"], "destination": config["XPDR"]["UUID"], "data": str(outer["message"])}

    print "Encrypted outer message"
    rsp = uploadMessage(msg)
    return rsp

def getMessages():
    msgs = downloadMessages()["download"]
    output = {}
    for m in msgs:
        source = m["Source"]
        data = m["Message"]
        id = m["MessageID"]
        output[id] = {"Source": source, "Message": decrypt(data, source)["message"]}
        print "Decrypted message: %s" % id

    return output

if not "KEY" in config:
    register()

node = keyInfo(config["KEY"])["data"]["NODE"]

while True:
    msgs = getMessages()
    for msg in msgs:
        print "ID..: %s" % msg
        print "To..: %s" % node
        print "From: %s" % msgs[msg]["Source"]
        print "Data: %s\n" % msgs[msg]["Message"]
