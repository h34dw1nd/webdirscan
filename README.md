# 简介

`webdirscan`是一个炒鸡简单的多线程Web目录扫描工具。

# ChangLog

2017-08-29
增加功能：
1、从文件中导入扫描列表
2、扫描网段主机的网站目录

# 安装

使用Python语言编写

第三方模块只用了`requests`,所以`clone`以后只需要安装`requests`模块即可。

```
git clone https://github.com/Strikersb/webdirscan.git
pip install requests
```

安装完成。

# 使用方法

```
usage: webdirscan.py [-h] [--host SCANSITE] [-d SCANDICT] [-o SCANOUTPUT]
                     [-t THREADNUM] [-f SCANINPUT]

optional arguments:
  -h, --help            show this help message and exit
  --host SCANSITE       The website to be scanned
  -d SCANDICT, --dict SCANDICT
                        Dictionary for scanning
  -o SCANOUTPUT, --output SCANOUTPUT
                        Results saved files
  -t THREADNUM, --thread THREADNUM
                        Number of threads running the program
  -f SCANINPUT, --file SCANINPUT
                        File include websites need to be scan
```

# Reference
https://github.com/Strikersb/webdirscan 
https://github.com/zer0h/httpscan

