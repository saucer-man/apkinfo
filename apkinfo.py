import argparse
import os
import sys
import zipfile
import subprocess
from apkutils import APK
import platform
import re
import binascii

shellfeatures = {
    "娜迦": [
        "libddog.so",
        "libchaosvmp.so",
        "libddog.so libfdog.so",
        "libfdog.so"
    ],
    "娜迦企业版": [
        "libedog.so"
    ],
    "梆梆": [
        "libsecexe.so",
        "libSecShell.so",
        "libsecmain.so"
    ],
    "梆梆企业版": [
        "libDexHelper.so",
        "libDexHelper-x86.so"
    ],
    "爱加密": [
        "libexec.so",
        "ijiami.dat",
        "libexecmain.so"
    ],
    "360": [
        "libjiagu.so; libjiagu.so",
        "libjiagu.so",
        "libjiagu_art.so; libjiagu.so",
        "libjiagu_x86.so",
        "libprotectClass.so",
        "libjiagu_art.so"
    ],
    "百度": [
        "libbaiduprotect.so"
    ],
    "阿里聚安全": [
        "libsgmain.so",
        "libmobisec.so",
        "aliprotect.dat",
        "libsgsecuritybody.so"
    ],
    "腾讯": [
        "libexec.so",
        "libtup.so",
        "lib/armeabi/mixz.dex",
        "libshell.so",
        "libshell.so; mix.dex; lib/armeabi/mix.dex",
        "lib/armeabi/mix.dex",
        "mix.dex"
    ],
    "腾讯御安全": [
        "libtosprotection.armeabi-v7a.so",
        "libtosprotection.armeabi.so",
        "libtosprotection.x86.so"
    ],
    "通付盾": [
        "libegis.so",
        "libNSaferOnly.so"
    ],
    "网秦": [
        "libnqshield.so"
    ],
    "网易易盾": [
        "libnesec.so"
    ],
    "APKProtect": [
        "libAPKProtect.so"
    ],
    "几维安全": [
        "libkwslinker.so",
        "libkwscmm.so",
        "libkwscr.so"
    ],
    "顶像科技": [
        "libx3g.so"
    ],

    "爱加密企业版": [
        "ijiami.ajm"
    ],

    "盛大": [
        "libapssec.so"
    ],
    "瑞星": [
        "librsprotect.so"
    ]
}


dex2jar_path = "./dex-tools-2.1/d2j-dex2jar.sh"
if platform.system().lower() == 'windows':
    dex2jar_path = "./dex-tools-2.1/d2j-dex2jar"


def shell_detect(apk_path, result_path):
    try:
        zipfiles = zipfile.ZipFile(apk_path)
        nameList = zipfiles.namelist()  # 得到压缩包里所有文件
        zipfiles.extractall(path=os.path.join(
            result_path, "files"))  # 解压zip到result目录下

        for fileName in nameList:
            for shell in shellfeatures.keys():
                if shell in fileName:
                    shellType = shellfeatures[shell]
                    return True, shellType
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


def manifest(apk, result_path):

    with open(os.path.join(result_path, "AndroidManifest.xml"), "w") as f:
        f.write(apk.get_manifest())

    print(
        f"基础信息：package: {apk.package_name} Version: {apk._version_name} MainActivity: {apk.get_manifest_main_activities()}")


def signinfo(apk: APK):
    try:
        # 获取签名信息
        for k, _ in apk.get_certs():
            print(f"签名信息：Signer:{k}")
    except:
        pass


def detect_strings(apk: APK, result_path):

    strings = set()
    for string in apk.get_dex_strings():
        try:
            strings.add(string.decode(encoding="UTF-8"))
        except:
            pass
    with open(os.path.join(result_path, "strings.txt"), "w") as f:
        for string in strings:
            f.write(f"{string}\n")

    urls = set()
    ips = set()
    hashes = set()
    sensitives = set()

    p = re.compile(
        '(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)')
    for string in strings:
        for url_flag in ["https://", "http://"]:
            if url_flag in string:
                urls.add(string)

        if p.match(string):
            ips.add(string)

        if len(string) == 32 or len(string) == 16:
            if re.match(r'^[a-z0-9]{16,32}$', string):
                hashes.add(string)

        sensitives_list = ["accessKey", "database", "ssh", "rdp", "smb", "mysql", "sqlserver", "oracle",
                           "ftp", "mongodb", "memcached", "postgresql", "telnet", "smtp", "pop3", "imap",
                           "vnc", "redis", "admin", "root", "config", "jdbc", ".properties", "aliyuncs",
                           "oss"]
        for forbid in sensitives_list:
            if forbid in string:
                sensitives.add(string)

        '''
        下面开始匹配AccessKey,自己测试发现:
        AccessKeyId 约为24位
        AccessKeySecret 约为30位
        '''

        if str(string).isalnum():
            # or re.match(r'^(?:(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])).{16,16}$', string):
            if re.match(r'^(?:(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])).{24,24}$', string):
                sensitives.add(string)

            if re.match(r'^(?:(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])).{30,30}$', string):
                sensitives.add(string)
    if urls:
        with open(os.path.join(result_path, "urls.txt"), "w") as f:
            f.write("\n".join(urls))
    if ips:
        with open(os.path.join(result_path, "ips.txt"), "w") as f:
            f.write("\n".join(ips))
    if hashes:
        with open(os.path.join(result_path, "hashes.txt"), "w") as f:
            f.write("\n".join(hashes))
    if sensitives:
        with open(os.path.join(result_path, "sensitives.txt"), "w") as f:
            f.write("\n".join(sensitives))


def analyse(apk_path, result_path):
    # 先解压 + 查壳
    print("开始查壳...")
    flag, shell_type = shell_detect(apk_path=apk_path, result_path=result_path)
    if flag:
        print(f"经检测，该apk使用了{shell_type}进行加固")
        return
    else:
        print("未检测到壳")

    # 再apk转jar
    print("apk包转jar...")
    flag = dex2jar(apk_path, result_path)
    if not flag:
        print("apk包转jar失败")
        return
    print("apk包转jar结束")

    apk = APK.from_file(apk_path)
    print("下面开始解析apk...")
    # 解析manifest获取apk信息
    manifest(apk, result_path)
    # 查看签名
    signinfo(apk)

    # 字符串解析，查找敏感字符串
    detect_strings(apk, result_path)
    print(f"{apk_path}分析结束,结果保存在{result_path}")


def main(apk_path):
    apk_path = os.path.abspath(apk_path)
    print(f"下面开始分析:{apk_path}")
    if not os.path.exists(apk_path):
        print(f"当前文件不存在:{apk_path}")
        return

    _, apkname = os.path.split(apk_path)
    local_path = os.path.abspath(os.path.dirname(__file__))
    result_path = os.path.join(local_path, "result", apkname)
    if not os.path.exists(result_path):
        os.makedirs(result_path)
    else:
        print("检测到文件已经分析过，将会覆盖")

    analyse(apk_path, result_path)


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
    else:
        for apk_path in apks:
            main(apk_path)
