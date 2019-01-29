## pip 集成
```shell
pip install tls-sig-api
```

## 调用接口

### 默认有效期
```python
import TLSSigAPI

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

api = TLSSigAPI.TLSSigAPI(1400000000, ecdsa_pri_key, ecdsa_pub_key)
sig = api.tls_gen_sig("xiaojun")
print(sig)
```

### 指定有效期
```python
import TLSSigAPI


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

api = TLSSigAPI.TLSSigAPI(1400000000, ecdsa_pri_key, ecdsa_pub_key)
sig = api.tls_gen_sig("xiaojun", 24*3600*180)
print(sig)
```