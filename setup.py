# -*- coding: utf-8 -*-
# @Time    : 2020/12/18 22:04:38
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : setup.py
# @Software: Visual Studio Code


import setuptools


def do_setup(**kwargs):
    try:
        setuptools.setup(**kwargs)
    except (SystemExit, Exception) as e:
        exit(1)


long_description = '''

An email detected library. It's support to detect the header, body and attachment.
It's support to parse the attachment type of ole, rtf, zip and so on.

## Insatall

```
$ pip install mmpi
```

mark：`windows` install `yara-python`，download from [here](https://github.com/VirusTotal/yara-python/releases)

## Usage

### 1. Command

```
$ mmpi-run $email_path
```

### 2. Quick Start

```
from mmpi import mmpi


def main():
    emp = mmpi()
    emp.parse('test.eml')
    report = emp.get_report()
    print(report)


if __name__ == "__main__":
    main()

```
'''

do_setup(
    name="mmpi",
    version="0.1.1",
    author="ddvv",
    author_email="dadavivi512@gmail.com",
    description="email detected library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/a232319779/mmpi",
    packages=setuptools.find_packages(exclude=["tests"]),
    entry_points={
        "console_scripts": [
            "mmpi-run = mmpi.main:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    keywords=[],
    license="MIT",
    include_package_data=True,
    install_requires=[
        "olefile==0.46", "yara-python==4.0.2",
    ],
)
