import pgpy, json, uuid
import database
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

with open('config.json', 'r') as configfile:
    config = json.load(configfile)

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
        db = database.connect()
        if key.is_expired:
            return False
        uuid.UUID(keydata["NODE"])
        uuid.UUID(keydata["XPDR"])

        if database.requestData(db, "Nodes", "NodeID", keydata["NODE"]):
            return False # UUID in use
        if not database.requestData(db, "Nodes", "NodeID", keydata["XPDR"]):
            if keydata["NODE"] == keydata["XPDR"]: return True # Candidate is a root XPDR
            return False # Parent XPDR non-existant
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

def encrypt(message, sender, recipient):
    output = {"success": False, "message": ""}
    pubkey = None
    privkey = None
    snode = database.getNode(sender, True)
    if not snode:
        output["error"] = "invalidSenderNode"
        return output
    rnode = database.getNode(recipient, True)
    if not rnode:
        output["error"] = "invalidRecipientNode"
        return output
    pubkey = keyInfo(rnode["PublicKey"])["public"]
    try:
        privkey = keyInfo(snode["PublicKey"])["private"]
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

def decrypt(message, sender, recipient):
    output = {"success": False, "message": ""}
    pubkey = None
    privkey = None
    snode = database.getNode(sender, True)
    if not snode:
        output["error"] = "invalidSenderNode"
        return output
    rnode = database.getNode(recipient, True)
    if not rnode:
        output["error"] = "invalidRecipientNode"
        return output
    pubkey = keyInfo(snode["PublicKey"])["public"]
    try:
        privkey = keyInfo(rnode["PublicKey"])["private"]
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
