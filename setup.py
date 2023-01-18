# -*- coding: utf-8 -*-
# @Time    : 2020/12/18 22:04:38
# @Author  : ddvv
# @Site    : https://ddvvmmzz.github.io
# @File    : setup.py
# @Software: Visual Studio Code


import setuptools


def read_version():
    """
    读取打包的版本信息
    """
    with open("./mmpi/version.py", "r", encoding="utf8") as f:
        for data in f.readlines():
            if data.startswith("NEXTB_MMPI_VERSION"):
                data = data.replace(" ", "")
                version = data.split("=")[-1][1:-1]
                return version
    # 默认返回
    return "0.2.1"


def read_readme():
    """
    读取README信息
    """
    with open("./README.md", "r", encoding="utf8") as f:
        return f.read()


def do_setup(**kwargs):
    try:
        setuptools.setup(**kwargs)
    except (SystemExit, Exception) as e:
        exit(1)


version = read_version()
long_description = read_readme()

do_setup(
    name="mmpi",
    version=version,
    author="ddvv",
    author_email="dadavivi512@gmail.com",
    description="email detected library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/a232319779/mmpi",
    packages=setuptools.find_packages(exclude=["tests"]),
    entry_points={
        "console_scripts": [
            "nextb-mmpi-run = mmpi.cli.cli_mmpi_run:run",
            "nextb-mmpi-scan = mmpi.cli.cli_mmpi_scan:run",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    keywords=[],
    license="MIT",
    include_package_data=True,
    install_requires=["olefile==0.46", "yara-python", "colorama==0.4.6"],
)
