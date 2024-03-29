# MMPI

`mmpi`，一款邮件快速检测python库，基于[`community`](https://github.com/cuckoosandbox/community)框架设计开发。支持对邮件头、邮件正文、邮件附件的检测，并输出检测结果。

## 一、安装

```
$ pip install mmpi
```

备注：`windows`安装`yara-python`，可以从[这里](https://pypi.org/project/yara-python/#files)下载，再使用`pip install yara_python-xx-xx-xx-win_amd64.whl`进行安装

## 二、使用

### 2.1 命令行工具

|命令行|说明|使用示例|结果输出|
|----|----|----|----|
|nextb-mmpi-scan|使用nextb-mmpi-scan工具扫描指定的邮件目录或者邮件文件|`nextb-mmpi-scan -s $email_dir`|输出格式参考[扫描结果](#三扫描结果输出)|
|nextb-mmpi-run|使用nextb-mmpi-run工具扫描指定的邮件文件,并返回完整报告|`nextb-mmpi-run -f $email_file`|输出格式参考[报告格式](#四报告格式)|

### 2.2 快速开始

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

## 三、扫描结果输出

扫描输出格式如下

```
> nextb-mmpi-scan.exe -s .
nextb-mmpi-scan扫描中: 100%|████████████████████████████████████████████████████████████████████████████████████| 11/11 [00:00<00:00, 23.35eml/s]
+----------+--------------------+
| 邮件名称 | NextB-mmpi命中标签 |
+----------+--------------------+
| .\1.eml  |       未检出       |
| .\10.eml |   spam_detection   |
| .\11.eml |       未检出       |
| .\2.eml  |       未检出       |
| .\3.eml  |       未检出       |
| .\4.eml  |  invalid_zip_file  |
| .\5.eml  | ole_type_not_match |
| .\6.eml  |       未检出       |
| .\7.eml  |   spam_detection   |
| .\8.eml  |       未检出       |
| .\9.eml  |   spam_detection   |
+----------+--------------------+
```

## 四、报告格式

包含固定字段：

* `headers`：邮件头基本信息
* `body`：邮件正文，text和html格式
* `attachments`：附件列表
* `signatures`：检测标签

动态字段：

* `vba`：宏代码
* `rtf`：rtf信息
* `zip`：压缩包信息

``` json
# 示例1
{
    "headers": [
        {
            "From": [
                {
                    "name": "Mohd Mukhriz Ramli (MLNG/GNE)",
                    "addr": "info@vm1599159.3ssd.had.wf"
                }
            ],
            "To": [
                {
                    "name": "",
                    "addr": ""
                }
            ],
            "Subject": "Re: Proforma Invoice",
            "Date": "2020-11-24 12:37:38 UTC+01:00",
            "X-Originating-IP": []
        }
    ],
    "body": [
        {
            "type": "text",
            "content": " \nDEAR SIR, \n\nPLEASE SIGN THE PROFORMA INVOICE SO THAT I CAN PAY AS SOON AS POSSIBLE.\n\nATTACHED IS THE PROFORMA INVOICE,\n\nPLEASE REPLY QUICKLY, \n\nTHANKS & REGARDS' \n\nRAJASHEKAR \n\n Dubai I Kuwait I Saudi Arabia I India I Egypt \nKuwait: +965 22261501 \nSaudi Arabia: +966 920033029 \nUAE: +971 42431343 \nEmail ID: help@rehlat.co [1]m\n \n\nLinks:\n------\n[1]\nhttps://deref-mail.com/mail/client/OV1N7sILlK8/dereferrer/?redirectUrl=https%3A%2F%2Fe.mail.ru%2Fcompose%2F%3Fmailto%3Dmailto%253ahelp%40rehlat.com"
        }
    ],
    "attachments": [
        {
            "type": "doc",
            "filename": "Proforma Invoice.doc",
            "filesize": 1826535,
            "md5": "558c4aa596b0c4259182253a86b35e8c",
            "sha1": "63982d410879c09ca090a64873bc582fcc7d802b"
        }
    ],
    "vba": [],
    "rtf": [
        {
            "is_ole": true,
            "format_id": 2,
            "format_type": "Embedded",
            "class_name": "EQUATion.3",
            "data_size": 912305,
            "md5": "a5cee525de80eb537cfea247271ad714"
        }
    ],
    "signatures": [
        {
            "name": "rtf_suspicious_detected",
            "description": "RTF Suspicious Detected",
            "severity": 3,
            "marks": [
                {
                    "type": "rtf",
                    "tag": "rtf_suspicious_detected"
                }
            ],
            "markcount": 1
        },
        {
            "name": "rtf_exploit_detected",
            "description": "RTF Exploit Detected",
            "severity": 9,
            "marks": [
                {
                    "type": "rtf",
                    "tag": "rtf_exploit_detected"
                }
            ],
            "markcount": 1
        }
    ]
}

# 示例2
{
    "headers": [
        {
            "From": [
                {
                    "name": "Pagon Favre | Purchase",
                    "addr": "pagon@orchutiyekyahai.lol"
                }
            ],
            "To": [
                {
                    "name": "",
                    "addr": "sujata@hilden.in"
                }
            ],
            "Subject": "Purchase Order - 19122020 [Early Dispatch Required]",
            "Date": "2020-12-17 13:48:57 UTC-08:00",
            "X-Originating-IP": []
        }
    ],
    "body": [],
    "attachments": [
        {
            "type": "pps",
            "filename": "Order Details.pps",
            "filesize": 130048,
            "md5": "9e6f2637079a311344f3cf2546de6a88",
            "sha1": "ff4da8a90127f5a6feec7af650fa7014050d25c2"
        },
        {
            "type": "ppt",
            "filename": "Purchase Order 19122020.ppt",
            "filesize": 130048,
            "md5": "9e6f2637079a311344f3cf2546de6a88",
            "sha1": "ff4da8a90127f5a6feec7af650fa7014050d25c2"
        }
    ],
    "vba": [
        {
            "size": 23358,
            "code": "Attribute VB_Name = \"Module1\"\r\nSub Auto_CloSe()\r\n\r\nDim myChrysler As String\r\n\r\nDim myFord As String\r\n\r\nDim SistersRangeRover As String\r\n\r\nmyChrysler = decrypt(\"p\", \"3\") + decrypt(\"|\", \"9\") + decrypt(\"o\", \"7\") + decrypt(\"}\", \"9\") + decrypt(\"c\", \"2\")\r\n\r\nSistersRangeRover = \" http://%999%999@j.mp/asdnabsdjncjnkk\"\r\n\r\n
            ....
            "
        }
    ],
    "signatures": [
        {
            "name": "yara_detected",
            "description": "detected from yara rule",
            "severity": 9,
            "marks": [
                {
                    "type": "vba",
                    "tag": "obfuscate_macros",
                    "description": "obfuscate macros",
                    "severity": 6
                },
                {
                    "type": "vba",
                    "tag": "exec_macros",
                    "description": "exec macros",
                    "severity": 9
                }
            ],
            "markcount": 2
        }
    ]
}
# 示例3
{
    "headers": [
        {
            "From": [
                {
                    "name": "\u7231\u83f2\u7684\u86df\u9f99",
                    "addr": "653518994@qq.com"
                }
            ],
            "To": [],
            "Subject": "\u7231\u83f2\u7684\u86df\u9f99 \u5bc4\u6765\u7684\u8d3a\u5361",
            "Date": "2008-04-26 11:09:07 UTC+08:00",
            "X-Originating-IP": []
        }
    ],
    "body": [
        {
            "type": "text",
            "content": "\u7231\u83f2\u7684\u86df\u9f99 \u5bc4\u6765\u7684\u8d3a\u5361\u300a\u626b\u5893\u53bb\u300b \u56de\u8d60\u8d3a\u5361\u7ed9\u60a8\u7684\u597d\u53cb\r\n\r\n \u5982\u679c\u60a8\u65e0\u6cd5\u67e5\u770b\u8d3a\u5361\uff0c\u70b9\u51fb\u6b64\u5904\u67e5\u770b\u3002\r\n     \u5c71\u6e05\u6c34\u79c0\u98ce\u5149\u597d\uff0c\u6708\u660e\u661f\u7a00\u796d\u626b\u591a\uff0c\u6e05\u660e\u8282\u5230\u4e86\uff0c\u4e00\u8d77\u626b\u5893\u53bb\u5427"
        }
    ],
    "attachments": [],
    "signatures": []
}
```

## 五、检测简要说明

### 5.1 邮件头检测

邮件头解析提取邮件发件人姓名、邮箱、收件人姓名、邮箱、邮件主题、发送时间、发送IP。

通过对发件人邮箱、发送IP做黑名单匹配，实现邮件头检测。

### 5.2 邮件正文检测

邮件正文解析提取text、html格式内容。

对html文件做分析，实现诸如探针检测、钓鱼检测、垃圾邮件检测等检测逻辑。

### 5.3 邮件附件检测

邮件附件检测，支持以下文件格式：

* `ole`文件格式：如`doc`、`xls`等，提取其中的`vba`宏代码、`模板注入`链接
* `zip`文件格式：提取压缩文件列表，统计文件名、文件格式等
* `rtf`文件格式：解析内嵌`ole`对象等
* 其他文件格式：如`PE`可执行文件

检测逻辑包括：

* 基本信息规则检测
* `yara`规则检测

## 六、感谢

* neil
* [cuckoosandbox](https://github.com/cuckoosandbox/community)
* [decalage2](https://github.com/decalage2)