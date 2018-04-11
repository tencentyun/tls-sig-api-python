#! /usr/bin/python
# coding:utf-8

# 此文件是 tls sig api 的 python 另一种实现
# 使用了 python ecdsa 开发库

__author__ = "tls@tencent.com"
__date__ = "$Oct 2, 2016 11:17:43 PM"

import base64
import zlib
import json
import time

# python ecdsa 开发库请到 https://github.com/warner/python-ecdsa
# 或者 tls 技术支持分享的链接 http://share.weiyun.com/24b674bced4f84ecbbe6a7945738b9f4
# 下载，下载完毕之后进入其根目录，运行下面的命令进行安装，
# python setup.py install
# ubuntu 用户可能需要添加 sudo
# 由于 python ecdsa 这个开发库仅支持 ec 格式的私钥，从腾讯云下载的私钥格式是
# pk #8 的格式，需要使用 openssl 命令进行转换，或者使用我们工具包中的 openssl 进行转换
# 下面是转换命令
# openssl ec -outform PEM -inform PEM -in private.pem -out private_ec.pem
# -in 后面的传入下载的私钥 -out 后面是转换后的私钥文件

from ecdsa import SigningKey,util
import hashlib

# 这里请填写应用自己的私钥
ecdsa_pri_key = """
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIEJDBDY4KVdj3dPBacADreB772ok45A57YWrUUvc5fMQoAcGBSuBBAAK
oUQDQgAEaPVFHhWqRDnKnVlyU5JIzXOUyOJd/pPUwhLUovf+PYBm7otRBptnvJ4E
oJ4qeSJNG0v4XdiqM3mtChkhUEFT3Q==
-----END EC PRIVATE KEY-----
"""

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
        fix_str = "TLS.appid_at_3rd:"+m["TLS.appid_at_3rd"]+"\n" \
                  +"TLS.account_type:"+m["TLS.account_type"]+"\n" \
                  +"TLS.identifier:"+m["TLS.identifier"]+"\n" \
                  +"TLS.sdk_appid:"+m["TLS.sdk_appid"]+"\n" \
                  +"TLS.time:"+m["TLS.time"]+"\n" \
                  +"TLS.expire_after:"+m["TLS.expire_after"]+"\n"
        return fix_str

    def tls_gen_sig(self, identifier):
        self.__identifier = identifier
        m = self.__create_dict()
        fix_str = self.__encode_to_fix_str(m)
        pk_loaded = self.__get_pri_key()
        sig_field = pk_loaded.sign(fix_str, hashfunc=hashlib.sha256, sigencode=util.sigencode_der)
        sig_field_base64 = base64.b64encode(sig_field)
        m["TLS.sig"] = sig_field_base64
        json_str = json.dumps(m)
        sig_cmpressed = zlib.compress(json_str)
        base64_sig = base64_encode_url(sig_cmpressed)
        return base64_sig 

def main():
    api = TLSSigAPI(1400001052, ecdsa_pri_key)
    sig = api.tls_gen_sig("xiaojun")
    print sig

if __name__ == "__main__":
    main()
