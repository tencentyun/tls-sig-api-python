#! /usr/bin/python
# coding:utf-8

import OpenSSL
import base64
import zlib
import json
import time

ecdsa_pri_key = """
-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgK55Mnxa+AH7tvzvAyfxW
aN1rZdL0Xv2hyg3k2eqjeHyhRANCAAQvkz6T2Or8EEzgF0lWBF0RtrxjJYUF6RqM
2JUDAP4UD/cIwhGTYlWC2ZRPZEvaXZJapz2Y2c2TwcgW13sAnIKZ
-----END PRIVATE KEY-----
"""

ecdsa_pub_key = """
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEL5M+k9jq/BBM4BdJVgRdEba8YyWFBeka
jNiVAwD+FA/3CMIRk2JVgtmUT2RL2l2SWqc9mNnNk8HIFtd7AJyCmQ==
-----END PUBLIC KEY-----
"""

def list_all_curves():
    list = OpenSSL.crypto.get_elliptic_curves()
    for element in list:
        print(element)


def get_prime256v1():
    print(OpenSSL.crypto.get_elliptic_curve('prime256v1'))


def base64_encode_url(data):
    base64_data = base64.b64encode(data)
    base64_data = base64_data.replace('+', '*')
    base64_data = base64_data.replace('/', '-')
    base64_data = base64_data.replace('=', '_')
    return base64_data

def base64_decode_url(base64_data):
    base64_data = base64_data.replace('*', '+')
    base64_data = base64_data.replace('-', '/')
    base64_data = base64_data.replace('_', '=')
    raw_data = base64.b64decode(base64_data)
    return raw_data

class TLSSigAPI:
    """"""
    
    __acctype = 0
    __identifier = ""
    __appid3rd = ""
    __sdkappid = 0
    __version = 20151204
    __expire = 3600*24*180
    __pri_key = ""
    __pub_key = ""
    _err_msg = "ok"
    
    def __get_pri_key(self):
        return OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.__pri_key);

    def __get_pub_key(self):
        print(self.__pub_key)
        return OpenSSL.crypto.load_publickey(OpenSSL.crypto.FILETYPE_PEM, self.__pub_key);
    
    def __init__(self, sdkappid, pri_key, pub_key):
        self.__sdkappid = sdkappid
        self.__pri_key = pri_key
        self.__pub_key = pub_key

    def __create_dict(self):
        m = {}
        m["TLS.account_type"] = "%d" % self.__acctype
        m["TLS.identifier"] = "%s" % self.__identifier
        m["TLS.appid_at_3rd"] = "%s" % self.__appid3rd
        m["TLS.sdk_appid"] = "%d" % self.__sdkappid
        m["TLS.expire_after"] = "%d" % self.__expire
        m["TLS.version"] = "%d" % self.__version
        m["TLS.time"] = "%d" % time.time()
        return m

    def __encode_to_fix_str(self, m):
        fix_str = "TLS.appid_at_3rd:"+m["TLS.appid_at_3rd"]+"\n" \
                  +"TLS.account_type:"+m["TLS.account_type"]+"\n" \
                  +"TLS.identifier:"+m["TLS.identifier"]+"\n" \
                  +"TLS.sdk_appid:"+m["TLS.sdk_appid"]+"\n" \
                  +"TLS.time:"+m["TLS.time"]+"\n" \
                  +"TLS.expire_after:"+m["TLS.expire_after"]+"\n"
        return fix_str
    
    def __check_field(self, m):
        if m["TLS.identifier"] != self.__identifier:
            self._err_msg = "identifier %s in req and identifier %s in tlssig not match" % (self.__identifier, m["TLS.identifier"])
            return -1
        if atoi(m["TLS.sdk_appid"]) != self.__sdkappid:
            self._err_msg = "sdkappid %d in req and identifier %s in tlssig not match" % (self.__identifier, m["TLS.sdk_appid"])
            return -2
        current_time = time.time()
        if atoi(m["TLS.expire_after"])+atoi(m["TLS.time"]) < current_time:
            self._err_msg = "tls sig expired expire %s add init time %s lower than current time %d" % (m["TLS.expire_after"], m["TLS.time"], current_time)
            return -3,
        return atoi(m["TLS.expire_after"]), atoi(m["TLS.time"])      

    def tls_gen_sig(self, identifier):
        self.__identifier = identifier

        m = self.__create_dict()
        fix_str = self.__encode_to_fix_str(m)
        pk_loaded = self.__get_pri_key()
        sig_field = OpenSSL.crypto.sign(pk_loaded, fix_str, "sha256");
        sig_field_base64 = base64.b64encode(sig_field)
        m["TLS.sig"] = sig_field_base64
        json_str = json.dumps(m)
        sig_cmpressed = zlib.compress(json_str)
        base64_sig = base64_encode_url(sig_cmpressed)
        return base64_sig
		
    def gen_sig(self, identifier, expire=3600*24*180):
        self.__expire = expire
        return self.tls_gen_sig(identifier)
    
    def tls_verify_sig(self, tlssig, identifier):
        self.__identifier = identifier
        
        sig_cmpressed = base64_decode_url(tlssig)
        json_str = zlib.decompress(sig_cmpressed)
        m = json.loads(json_str)
        fix_str = self.__encode_to_fix_str(m)
        pubkey_loaded = self.__get_pub_key()
        sig_field = base64.b64decode(m["TLS.sig"])
        ret = OpenSSL.crypto.verify(pubkey_loaded, sig_field, fix_str, "sha256")
        print(ret)

def main():
    api = TLSSigAPI(1400001052, ecdsa_pri_key, ecdsa_pub_key)
    sig = api.tls_gen_sig("xiaojun")
    print(sig)


if __name__ == "__main__":
    main()
