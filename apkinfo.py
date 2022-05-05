import argparse
import os
import sys
import zipfile
import subprocess
from apkutils import APK
import platform
import re
import json


class APKInfo():
    def __init__(self, apk_path):
        self.apk_path = os.path.abspath(self.apk_path)
        self.base_path = os.path.abspath(os.path.dirname(__file__))
        self.apk = None
        self.result_path = None
        self.apk_name = None
        self.shell_type = None
        self.patterns = None
        self.pattern_file = None
        self.shellfeatures = None
        self.check()

    def shell_detect(self):
        try:
            zipfiles = zipfile.ZipFile(self.apk_path)
            namelist = zipfiles.namelist()  # 得到压缩包里所有文件
            # zipfiles.extractall(path=os.path.join(
            #     self.result_path, "files"))  # 解压zip到result目录下

            for filename in namelist:
                for k, v in self.shellfeatures.items():
                    for shell in v:
                        if shell in filename:
                            shell_type = k
                            return True, shell_type
        except:
            pass
        return False, "未加壳"

    def dex2jar(apk_path, savePath):
        try:
            subprocess.run(
                f"{dex2jar_path} --force {apk_path} --output {os.path.join(savePath, 'classed-dex2jar.jar')}", shell=True)
            return True
        except:
            pass
        return False

    def manifest(self):

        with open(os.path.join(self.result_path, "AndroidManifest.xml"), "w") as f:
            f.write(self.apk.get_manifest())

        print(f"{self.apkname}基础信息：package: {self.apk.package_name} Version: {self.apk._version_name} MainActivity: {self.apk.get_manifest_main_activities()}")

    def signinfo(self):
        try:
            # 获取签名信息
            for k, _ in self.apk.get_certs():
                print(f"{self.apkname}签名信息：Signer:{k}")
        except:
            pass

    def finder(self, pattern, strings):
        matcher = re.compile(pattern)
        found = []
        for string in strings:
            mo = matcher.search(string)
            if mo:
                found.append(mo.group())
        return sorted(list(set(found)))

    def save(self, name, found):
        if not found:
            return
        with open(os.path.join(self.result_path, name), "a") as f:
            f.write("\n".join(found))

    def detect_strings(self):
        strings = set()
        for string in self.apk.get_dex_strings():
            try:
                strings.add(string.decode(encoding="UTF-8"))
            except:
                pass
        with open(os.path.join(self.result_path, "strings.txt"), "w") as f:
            for string in strings:
                f.write(f"{string}\n")

        for name, pattern in self.patterns.items():
            if isinstance(pattern, list):
                for p in pattern:
                    found = self.finder(name, p, strings)
                    self.save(name, found)
            else:
                found = self.finder(name, pattern, strings)
                self.save(name, found)

    def check(self):
        print(f"下面开始分析:{self.apk_path}")
        if not os.path.exists(self.apk_path):
            raise(f"当前文件不存在")

        _, self.apkname = os.path.split(apk_path)
        result_path = os.path.join(self.base_path, "result", self.apkname)
        if not os.path.exists(result_path):
            os.makedirs(result_path)
        else:
            print(f"{self.apkname}: 检测到文件已经分析过，将会覆盖")
        self.pattern_file = os.path.join(self.base_path, "config", "keys.json")
        with open(self.pattern_file) as f:
            self.patterns = json.load(f)
        shell_path = os.path.join(self.base_path, "config", "shell.json")
        with open(shell_path) as f:
            self.shellfeatures = json.load(f)

    def analyse(self):
        # 先解压 + 查壳
        print(f"{self.apkname}: 开始查壳...")
        flag, self.shell_type = self.shell_detect()
        if flag:
            print(f"{self.apkname}: 经检测，该apk使用了{self.shell_type}进行加固")
            return
        else:
            print(f"{self.apkname}: 未检测到壳")

        self.apk = APK.from_file(self.apk_path)
        print(f"{self.apkname}: 下面开始解析apk...")
        # 解析manifest获取apk信息
        self.manifest()

        # 查看签名
        self.signinfo()

        # 字符串解析，查找敏感字符串
        self.detect_strings()
        print(f"{self.apkname}: 分析结束,结果保存在{self.result_path}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='apk信息提取')
    parser.add_argument('-a', '--apk',
                        help='指定apk路径')
    parser.add_argument('-d', '--dir',
                        help='指定apk路径')
    args = parser.parse_args()
    apks = []
    if args.apk:
        apks.append(args.apk)
    if args.dir:
        for filename in os.listdir(args.dir):
            if filename.endswith(".apk"):
                apks.append(os.path.join(args.dir, filename))
    if not apks:
        print(f"请使用-a或者-f指定apk")
        sys.exit()

    for apk_path in apks:
        try:
            apk = APKInfo(apk_path)
            apk.analyse()
        except Exception as e:
            print(f"{apk_path}出错: {e}")
