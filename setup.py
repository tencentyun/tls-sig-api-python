from setuptools import setup, find_packages

setup (
       name='tls-sig-api',
       version='1.0',
       packages=find_packages(),

       author_email='okhowang@tencent.com',

       py_modules=[
           'TLSSigAPI'
           ],
       install_requires=[
           'ecdsa',
           ],

       url='https://github.com/tencentyun/tls-sig-api-python',
       license='MIT',
       )
