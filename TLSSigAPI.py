import base64
import zlib
import json
import time

# python ecdsa 开发库请到 https://github.com/warner/python-ecdsa
# 或者 tls 技术支持分享的链接 http://share.weiyun.com/24b674bced4f84ecbbe6a7945738b9f4
# 下载，下载完毕之后进入其根目录，运行下面的命令进行安装，
# python setup.py install
# 下面是转换私钥格式命令
# openssl ec -outform PEM -inform PEM -in private.pem -out private_ec.pem
# -in 后面的传入下载的私钥 -out 后面是转换后的私钥文件

from ecdsa import SigningKey,util
import hashlib

# 这里请填写应用自己的私钥
ecdsa_pri_key = """
your_private_key
"""

def base64_encode_url(data):
    base64_data = base64.b64encode(data)
    # type(base64_data) ->bytes
    base64_data = bytes.decode(base64_data).replace('+', '*')
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
    __version = 20190114
    __expire = 3600*24*30       # 默认一个月，需要调整请自行修改
    __pri_key = ""
    __pub_key = ""
    _err_msg = "ok"
    

    def __get_pri_key(self):
        return self.__pri_key_loaded

    def __init__(self, sdkappid, pri_key):
        self.__sdkappid = sdkappid
        self.__pri_key = pri_key
        self.__pri_key_loaded = SigningKey.from_pem(self.__pri_key)

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
        fix_str = "TLS.appid_at_3rd:" + m["TLS.appid_at_3rd"] + "\n" \
                  + "TLS.account_type:" + m["TLS.account_type"] + "\n" \
                  + "TLS.identifier:" + m["TLS.identifier"] + "\n" \
                  + "TLS.sdk_appid:" + m["TLS.sdk_appid"] + "\n" \
                  + "TLS.time:" + m["TLS.time"] + "\n" \
                  + "TLS.expire_after:" + m["TLS.expire_after"] + "\n"
        return fix_str

    def tls_gen_sig(self, identifier):
        self.__identifier = identifier
        m = self.__create_dict()
        fix_str = self.__encode_to_fix_str(m)
        pk_loaded = self.__get_pri_key()
        sig_field = pk_loaded.sign(fix_str.encode(), hashfunc=hashlib.sha256, sigencode=util.sigencode_der)
        sig_field_base64 = base64.b64encode(sig_field)
        s2 = bytes.decode(sig_field_base64)
        m["TLS.sig"] = s2
        json_str = json.dumps(m)
        # type(json_str)  -> str
        sig_cmpressed = zlib.compress(json_str.encode())    # json_str bytes-like -> bytes
        # type(sig_cmpressed) ->bytes
        base64_sig = base64_encode_url(sig_cmpressed)   # sig_cmpressed bytes-like -> bytes
        return base64_sig

def main():
    api = TLSSigAPI(1400001052, ecdsa_pri_key)
    sig = api.tls_gen_sig("xiaojun")
    print sig

if __name__ == "__main__":
    main()
