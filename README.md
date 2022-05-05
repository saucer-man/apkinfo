## apkinfo

**一键解析app信息+检查敏感信息**

用法:
```
python3 -m pip install apkutils

python3 apkinfo -a path/to/app
python3 apkinfo -f dir/to/app
```

功能：

- 解压app
- 查壳
- manifest解析
- 签名查询
- 敏感信息查询
  - url、ips
  - 手机号、身份证、银行卡等
  - 其他敏感信息，比如oss key、数据库链接地址等
  - 如果想自定义关键词，直接编辑`config/keys.json`即可
