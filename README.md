## apkinfo

**一键解析app信息+检查敏感信息**

用法:
```
python3 -m pip install apkutils

python3 apkinfo -a path_for_app
python3 apkinfo -f dir_for_app
```

功能：

- 解压app
- 查壳
- dex2jar
- manifest解析
- 签名查询
- 敏感信息查询
  - url
  - ips
  - hashs
  - 其他敏感信息，比如key、数据库链接地址等

## 备注

参考 https://github.com/TheKingOfDuck/ApkAnalyser   但是原项目用起来报错了，所以自己重写了一个