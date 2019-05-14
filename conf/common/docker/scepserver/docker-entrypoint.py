#!/usr/bin/python3
# -*- coding:utf-8 -*-
import os
import stat
import subprocess
import sys
import warnings


CA_DIR = os.environ["SCEP_FILE_DEPOT"]


CA_INIT_CALL_ARGS = ["/usr/local/bin/scepserver", "ca", "-init",
                     "-depot", CA_DIR,
                     "-key-password", os.environ["SCEP_CA_PASS"],
                     "-country", "DE",
                     "-organization", "Zentral"]


CA_CRL_CALL_ARGS = ["/usr/bin/openssl", "ca",
                    "-config", "/etc/scep/openssl.conf",
                    "-gencrl",
                    "-passin", "env:SCEP_CA_PASS",
                    "-out", os.path.join(CA_DIR, "crl.pem")]


def gen_crl():
    subprocess.check_call(CA_CRL_CALL_ARGS)
    print("CRL generated")


def wait_for_ca():
    ca_cert = os.path.join(CA_DIR, "ca.pem")
    if not os.path.exists(ca_cert):
        subprocess.check_call(CA_INIT_CALL_ARGS)
        print("CA initialized")
    else:
        print("Found CA")
    st = os.stat(ca_cert)
    os.chmod(ca_cert, st.st_mode | stat.S_IRGRP | stat.S_IROTH)

    # create an empty index file if necessary
    index = os.path.join(CA_DIR, "index.txt")
    if not os.path.exists(index):
        with open(index, "w") as f:
            pass
        print("Empty index.txt file created")

    # create the crl number file if necessary
    crlnumber = os.path.join(CA_DIR, "crlnumber")
    if not os.path.exists(crlnumber):
        with open(crlnumber, "w") as f:
            f.write("01")  # 1 in hex
        print("Initial crlnumber file created")

    # generate the crl if necessary
    ca_crl = os.path.join(CA_DIR, "crl.pem")
    if not os.path.exists(ca_crl):
        gen_crl()


KNOWN_COMMANDS = {
    "runserver": ["/usr/local/bin/scepserver"],
    "gencrl": CA_CRL_CALL_ARGS,
}


if __name__ == '__main__':
    if len(sys.argv) < 2:
        warnings.warn("Not enough arguments.")
        sys.exit(2)
    cmd = sys.argv[1]
    args = KNOWN_COMMANDS.get(cmd, None)
    if args:
        filename = args[0]
        args.extend(sys.argv[2:])
        wait_for_ca()
        print('Launch known command "{}"'.format(cmd))
    else:
        filename = cmd
        args = sys.argv[1:]
    os.execvp(filename, args)
