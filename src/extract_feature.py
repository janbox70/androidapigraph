# coding=UTF-8
# python3

import logging
import json
import os
import shutil
import re
import multiprocessing
import traceback
from tqdm import tqdm
from datetime import datetime
from xml.dom import minidom
import profile

log_format = "%(asctime)s %(levelname)s - %(message)s"
log_file_format = "%(asctime)s %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=log_format)

logger = logging.getLogger(__file__)


def init_log_file(filename):
    """
    初始化日志文件。多次初始化时，替代上一个日志文件
    """
    logfile = logging.FileHandler(filename=filename, mode="a", encoding="utf-8")
    logfile.setFormatter(logging.Formatter(fmt=log_file_format))
    if len(logging.root.handlers) <= 1:
        logging.root.addHandler(logfile)
    else:
        logging.root.handlers[1] = logfile


class FeatureExtractor:
    """
    对APK进行解包，并提取 API的特征，用于 evolover, drebin 模型
    """

    def __init__(self, temp_path, conf_path="", reserve_smali=False):
        self.conf_path = conf_path
        self.temp_path = temp_path
        self.reserve_smali = reserve_smali

        self.packages = None
        self.pmap_r = dict()
        self.url_pattern = re.compile(r"https?://(?P<domain>(([a-z\d\-]+\.)+[a-z]+\b)|(\d\.){3}\d)")

        self.AndroidSuspiciousApiNameList = {"getExternalStorageDirectory", "getSimCountryIso", "execHttpRequest",
                                             "sendTextMessage", "getSubscriberId", "getDeviceId", "getPackageInfo",
                                             "getSystemService", "getWifiState", "setWifiEnabled", "setWifiDisabled",
                                             "Cipher"}
        self.OtherSuspiciousApiNameList = {"Landroid/telephony/SmsMessage;->getMessageBody",
                                           "Ljava/io/IOException;->printStackTrace", "Ljava/lang/Runtime;->exec"}
        self.OtherSuspiciousClassList = {"Lorg/apache/http/client/methods/HttpPost", "Ljava/net/HttpURLconnection"}
        self.NotLikeApiNameList = {"system/bin/su", "android/os/Exec"}

        self.prepare()

    def prepare(self):
        """
        准备配置数据
        """
        # family = ['android', 'google', 'java', 'javax', 'xml', 'apache', 'junit', 'json', 'dom']
        # correspond to the android.*, com.google.*, java.*, javax.*, org.xml.*,
        # org.apache.*, junit.*, org.json, and org.w3c.dom.* packages

        with open(os.path.join(self.conf_path, 'android_package.name'), 'r') as fp:
            packages = [package.strip() for package in fp.readlines()]
            logger.info('official package number: {}'.format(len(packages)))
            self.packages = packages

        # 装入权限/API映射表
        with open(os.path.join(self.conf_path, "SmallCasePScoutPermApiDict.json"), 'r') as fp:
            # 权限 -> API 映射表
            pmap = json.load(fp)
            # 转为 api -> 权限表
            for perm, apis in pmap.items():
                for api in apis:
                    # each api: classname, method, params[]，这里忽略参数
                    apiname = api[0] + ":" + api[1]  #
                    apiname = apiname.lower()
                    if apiname not in self.pmap_r:
                        self.pmap_r[apiname] = []
                    self.pmap_r[apiname].append(perm)

    def extract_feature(self, apkname, target_path):
        """
        apkname 已经去掉后缀
        """
        features = {
            "EvoloverApi": set(),  # classes+mothod, 用set消重
            "AndroidApi": dict(),  # Landroid开始的API信息

            "UsedPermissions": set(),
            "RestrictedApi": set(),
            "SuspiciousApi": set(),
            "URLDomain": set(),

            # from manifest.xml
            "RequestedPermission": set(),
            "Activity": set(),
            "Service": set(),
            "ContentProvider": set(),
            "BroadcastReceiver": set(),
            "HardwareComponents": set(),
            "IntentFilter": set(),
        }

        filedir = os.path.join(self.temp_path, apkname)

        # 从manifest 获取 drebin 特征
        manifestfile = os.path.join(filedir, "AndroidManifest.xml")
        self.extract_from_manifest(manifestfile, features)

        for dirpath, dirnames, filenames in os.walk(filedir):
            for filename in [f for f in filenames if f.endswith('.smali')]:
                self.extract_from_smali(os.path.join(dirpath, filename), features)

        # 处理权限信息
        for fullName, Api in features['AndroidApi'].items():
            api_class = Api['ApiClass'].replace("/", ".").replace("Landroid", "android").strip()
            apifullname = api_class + ":" + Api['ApiName']
            apifullname = apifullname.lower()
            if apifullname in self.pmap_r:
                for perm in self.pmap_r[apifullname]:
                    if perm in features['RequestedPermission']:
                        features['UsedPermissions'].add(perm)
                    else:
                        features['RestrictedApi'].add(Api['ApiClass'] + ":" + Api["ApiName"])

        # 保存 evovoler 特征
        self.save_list_to_file(os.path.join(target_path, "evolover", apkname + '.feature'),
                               sorted(features['EvoloverApi']))

        # 转换 drebin 特征，并保存
        # set 转为 list
        data_dict = dict((k + "List", list(sorted(v))) for k, v in sorted(features.items())
                         if k not in ['EvoloverApi', 'AndroidApi'])

        with open(os.path.join(target_path, "drebin", apkname + '.json'), 'w') as fp:
            json.dump(data_dict, fp, indent=2)

        # 保存为原先的兼容格式
        data_list = []
        for k, v in data_dict.items():
            for item in v:
                data_list.append(k + '_' + item)

        self.save_list_to_file(os.path.join(target_path, "drebin", apkname + '.data'),
                               sorted(data_list))

        # 复制 xml文件
        shutil.copyfile(manifestfile, os.path.join(target_path, "drebin", apkname + '.xml'))

        summary = dict((k, len(v)) for k, v in sorted(features.items()))
        logger.info("[{}] summary: {}".format(apkname, summary))

    def extract_from_smali(self, filename, features):
        with open(filename, "r") as fp:
            for line in fp.readlines():
                if "invoke-" in line:
                    self.proc_invoke_line(line, features)

                if "http" in line:
                    url_domain = self.extract_urldomain(line)
                    if url_domain:
                        features['URLDomain'].add(url_domain)
                        # logger.debug("URLDomain({}) found in {}".format(url_domain, line))

    def proc_invoke_line(self, line, features):
        for part in line.split(","):
            if ";->" in part:
                fullname = part.strip()
                api_parts = fullname.split(";->")
                api_class = api_parts[0].strip()
                method = api_parts[1].split("(")[0].strip()
                package = '/'.join(api_class.split('/')[:-1])
                normalized_name = api_class + ":" + method
                if package in self.packages:
                    features['EvoloverApi'].add(normalized_name)

                if fullname.startswith('Landroid'):
                    # 提取Android的API
                    if fullname not in features['AndroidApi']:
                        features['AndroidApi'][fullname] = {
                            'FullApi': fullname,
                            'ApiClass': api_class,
                            'ApiName': method,
                        }
                    if method in self.AndroidSuspiciousApiNameList:
                        features['SuspiciousApi'].add(normalized_name)
                elif api_class in self.OtherSuspiciousClassList:
                    features['SuspiciousApi'].add(normalized_name)
                elif api_class + ";->" + method in self.OtherSuspiciousApiNameList:
                    features['SuspiciousApi'].add(normalized_name)

        for item in self.NotLikeApiNameList:
            if item in line:
                features['SuspiciousApi'].add(item)

    def extract_urldomain(self, line):
        # 查找 ULR的domain
        m = re.search(self.url_pattern, line.lower())
        if m:
            domain = m.group('domain')
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        return None

    @staticmethod
    def extract_from_manifest(manifestfile, features):
        conf = {
            # key, tagname
            'RequestedPermission': "uses-permission",
            'Activity': "activity",
            'Service': "service",
            'ContentProvider': "provider",
            'BroadcastReceiver': "receiver",
            'HardwareComponents': "uses-feature",
            'IntentFilter': "action",
        }

        # todo: xml 的文件格式问题，可能导致异常
        with open(manifestfile, "r") as fp:
            text = fp.read()
            # check mal-format
            # 修复后，尽管可以打开xml，但部分内容不能正常提取。 这里暂时放弃修复，会丢弃整个样本
            # text = FeatureExtractor.fixup_mal_format(text)

            Dom = minidom.parseString(text)
            DomCollection = Dom.documentElement
            for key, tagName in conf.items():
                elements = DomCollection.getElementsByTagName(tagName)
                for item in elements:
                    if item.hasAttribute("android:name"):
                        features[key].add(item.getAttribute("android:name"))

    @staticmethod
    def fixup_mal_format(text):
        """
        把 xml中缺失的属性标签补上：
            android:=  换成  android:t1234=
        """
        pattern = re.compile(r"android:=")
        p = 0
        t = ""
        for m in re.finditer(pattern, text):
            t = t + text[p:m.start()] + "android:t{}=".format(m.start())
            p = m.end()
        t = t + text[p:]
        return t

    @staticmethod
    def save_list_to_file(filename, data):
        with open(filename, "w") as fp:
            for line in data:
                fp.write(line)
                fp.write("\n")

    @staticmethod
    def apktool(source_file, work_path):
        # 资源文件仅解压 manifest
        # cmd = 'apktool d ' + source_file + ' -o ' + work_path
        cmd = 'apktool d -r --force-manifest ' + source_file + ' -o ' + work_path
        os.system(cmd)

    def run_apk(self, apk: str, source_path, target_path):
        start = datetime.now()
        base_name = apk.replace(".apk", "")
        source_file = os.path.join(source_path, apk)
        work_path = os.path.join(self.temp_path, base_name)
        if os.path.exists(work_path):
            shutil.rmtree(work_path)

        # 复制到ramdisk，降低硬盘的IOPS
        shutil.copyfile(source_file, os.path.join(self.temp_path, apk))
        source_file = os.path.join(self.temp_path, apk)

        # 解包
        self.apktool(source_file, work_path)
        logger.info("[{}] apktool finished in {:.2f} sec".format(
            base_name, (datetime.now() - start).total_seconds()))
        #
        # 特征提取
        self.extract_feature(base_name, target_path)

        # 清空临时文件
        if not self.reserve_smali:
            shutil.rmtree(work_path)
            os.remove(source_file)

        logger.info("[{}] extract_feature finished in {:.2f} sec".format(
            base_name, (datetime.now() - start).total_seconds()))

    def run_batch(self, source_path: str, target_path: str, jobs=1):
        """
        非递归遍历源目录下所有的apk文件，批量解包提取特征，并存储结果到目标目录
        source_path: 源文件路径
        target_path: 目标文件路径
        """

        # 初始化输出目录
        if not os.path.exists(target_path):
            os.makedirs(target_path)
        for subdir in ["evolover", "drebin"]:
            subpath = os.path.join(target_path, subdir)
            if not os.path.exists(subpath):
                os.mkdir(subpath)

        apks = [fn for fn in os.listdir(source_path) if fn.endswith('.apk')]
        if jobs == 1 or len(apks) <= 1:
            n = 0
            for fn in tqdm(apks):
                n = n + 1
                logger.info("[%d] processing file: %s" % (n, fn))
                FeatureExtractor.proc_task(self, fn, source_path, target_path)
        else:
            logger.info("start processing %d files in %s, jobs=%d" % (len(apks), source_path, jobs))
            pbar = tqdm(total=len(apks))
            processing_num = min(len(apks), jobs)
            pool = multiprocessing.Pool(processing_num)
            for fn in apks:
                pool.apply_async(FeatureExtractor.proc_task, (self, fn, source_path, target_path),
                                 callback=lambda *arg: pbar.update())
            pool.close()
            pool.join()

    @staticmethod
    def proc_task(extractor, apk: str, source_path: str, target_path: str):
        try:
            extractor.run_apk(apk, source_path, target_path)
        except Exception as e:
            logger.error("Exception while processing(%s): %s\n%s" % (apk, e, traceback.format_exc()))
            pass


def run_batch_multi_year(jobs, start, years=1):
    # for server: by years
    year2disk = {2018: 7, 2017: 7, 2016: 7, 2015: 6, 2014: 6, 2013: 5, 2012: 5}
    source_p = "/home/disk{}/keti3/{}"
    target_p = "/home/disk1/feature/{}/normal"
    temp_path = "/home/disk1/ram_disk/temp"
    _extractor = FeatureExtractor(temp_path)
    for year in range(start, start - years, -1):
        source_path = source_p.format(year2disk[year], year)
        target_path = target_p.format(year)
        _extractor.run_batch(source_path, target_path, jobs=jobs)


def run_batch(jobs, data_path):
    # for local-test
    source_path = os.path.join(data_path, "input")
    target_path = os.path.join(data_path, "output")
    temp_path = os.path.join(data_path, "temp")
    _extractor = FeatureExtractor(temp_path)
    _extractor.run_batch(source_path, target_path, jobs=jobs)
    # 调试性能用
    # profile.run("_extractor.run_batch(filelist, jobs=1)", sort=2)


if __name__ == "__main__":
    init_log_file("extract_feature.log")
    jobs = 40
    # 服务器运行多年度数据，以2018开始，往前 years 年
    # run_batch_multi_year(jobs=jobs, start=2018, years=4)

    # 目录结构预设
    run_batch(jobs, data_path="../data")
