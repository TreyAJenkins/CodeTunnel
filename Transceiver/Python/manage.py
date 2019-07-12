import time
start = time.time()
import json, uuid
import IPython
import database, cryptic
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

with open('config.json', 'r') as configfile:
    config = json.load(configfile)

def finish():
    print "\nExecution Time: " + str(round(time.time() - start, 3))
    exit(0)

def genXPDR():
    print "config.xpdr.name....: " + config["XPDR"]["NAME"]
    print "config.xpdr.location: " + config["XPDR"]["LOCATION"]
    print "config.xpdr.uuid....: " + config["XPDR"]["UUID"]
    #db = database.connect()
    id = str(uuid.UUID(config["XPDR"]["UUID"])).upper() # Verify valid UUID
    jsx = {"NODE": id, "XPDR": id} # Where UUID: node UUID, XPDR: parent xpdr UUID,
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    uid = pgpy.PGPUID.new(config["XPDR"]["NAME"], comment='Transponder', email=json.dumps(jsx))
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.Certify},
            hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
            ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
            compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])

    status = database.createNode(key, True)
    print status
    return key

def testNode(id="", name="Test Node", type="XMTR"):
    if id == "": id = str(uuid.uuid4())
    key = cryptic.genKey(name, type, id)
    return key

IPython.embed()
