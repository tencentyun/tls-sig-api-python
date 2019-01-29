## pip 集成
```shell
pip install tls-sig-api
```

## 调用接口

### 默认有效期
```python
import TLSSigAPI


api = TLSSigAPI.TLSSigAPI(1400000000, pri_key_content, pub_key_content)
sig = api.tls_gen_sig("xiaojun")
print(sig)
```

### 指定有效期
```python
import TLSSigAPI


api = TLSSigAPI.TLSSigAPI(1400000000, pri_key_content, pub_key_content)
sig = api.tls_gen_sig("xiaojun", 24*3600*180)
print(sig)
```
