from setuptools import setup, find_packages

setup (
        name='tls-sig-api',
        version='1.3',
        packages=find_packages(),

        author_email='weijunyi@tencent.com',

        py_modules=[
            'TLSSigAPI'
            ],
        install_requires=[
            'pyOpenSSL',
            ],

        url='https://github.com/tencentyun/tls-sig-api-python',
        license='MIT',
        )
