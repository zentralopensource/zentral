#!/usr/bin/python
from datetime import datetime
import os
import plistlib
import re
import subprocess
import time


LOG_ERR_RE = re.compile("((Too many open files)|(System performance limits exceeded))")
LEGACY_LOG_FILE = "/var/log/zentral_osqueryd_stderr.log"


def get_last_exit_code():
    p = subprocess.Popen(["/bin/launchctl", "list", "com.facebook.osqueryd"],
                         stdout=subprocess.PIPE)
    stdout = p.communicate()[0]
    for line in stdout.splitlines():
        line = line.strip().strip(";")
        if "LastExitStatus".upper() in line.upper():
            return int(line.split()[-1])
    return None


def create_log_dir_if_missing(filename):
    dir_path = os.path.dirname(filename)
    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)


def inspect_logfile(filename):
    if not os.path.exists(filename):
        return {}
    stat_result = os.stat(filename)
    d = {"filename": os.path.realpath(filename),
         "device": stat_result.st_dev,
         "inode": stat_result.st_ino,
         "ctime": datetime.utcfromtimestamp(stat_result.st_ctime),
         "mtime": datetime.utcfromtimestamp(stat_result.st_mtime),
         "timestamp": datetime.utcnow()}

    err_num = 0
    line_num = 0
    with open(filename) as f:
        for line in f.readlines():
            line_num += 1
            if LOG_ERR_RE.search(line):
                err_num += 1

    d["line_num"] = line_num
    d["err_num"] = err_num
    return d


def read_results(filename):
    if os.path.exists(filename):
        return plistlib.readPlist(filename)


def write_results(results, filename):
    plistlib.writePlist(results, filename)


def reset(database_path, launchd_plist):
    # stop osqueryd
    subprocess.check_call(["/bin/launchctl", "unload", launchd_plist])
    time.sleep(1)
    # delete db
    for filename in os.listdir(database_path):
        os.unlink(os.path.join(database_path, filename))
    # start osqueryd
    subprocess.check_call(["/bin/launchctl", "load", launchd_plist])


def find_log_files(log_dir_path):
    files = {}
    if not os.path.isdir(log_dir_path):
        return files
    for filename in os.listdir(log_dir_path):
        if not filename.endswith(".log"):
            fd = dict(zip(("prefix", "level", "timestamp"),
                          filename.split(".", 2)))
        else:
            fd = {}
        path = os.path.join(log_dir_path, filename)
        fd["real_path"] = os.path.realpath(path)
        fd["size"] = os.path.getsize(path)
        fd["link"] = os.path.islink(path)
        ts = fd.get("timestamp")
        if ts:
            fd["timestamp"] = datetime.strptime(ts, "%Y%m%d-%H%M%S.%f")
        files[path] = fd
    for path, fd in files.items():
        if fd["link"]:
            real_path = os.path.realpath(path)
            for path2, fd2 in files.items():
                if path2 != path and fd2["real_path"] == real_path:
                    fd2["current"] = True
                    break
    return files


def purge_log_files(log_file):
    log_dir_path = os.path.dirname(log_file)
    for file_path, file_d in find_log_files(log_dir_path).items():
        if not file_d.get("current") and not file_d.get("link"):
            os.unlink(file_path)
    if os.path.exists(LEGACY_LOG_FILE):
        os.unlink(LEGACY_LOG_FILE)


def run(launchd_plist, database_path, log_file, registry_file):
    pr = read_results(registry_file)
    create_log_dir_if_missing(log_file)
    r = inspect_logfile(log_file)
    last_exit_code = get_last_exit_code()
    if r.get("err_num", True) or last_exit_code > 0:
        # errors in log file or log file not found or last exit with errors => reset
        reset(database_path, launchd_plist)
        reset_dict = r.copy()
        reset_dict["timestamp"] = datetime.utcnow()
        r["last_reset"] = reset_dict
    else:
        if pr:
            r["last_reset"] = pr.get("last_reset") or False
        else:
            r["last_reset"] = False
    write_results(r, registry_file)
    purge_log_files(log_file)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("launchd_plist", help="osqueryd launchd plist")
    parser.add_argument("database_path", help="osqueryd database path")
    parser.add_argument("log_file", help="osqueryd log file to watch")
    parser.add_argument("registry_file", help="registry file to keep track of the log file inspections")
    args = parser.parse_args()
    run(args.launchd_plist, args.database_path, args.log_file, args.registry_file)
