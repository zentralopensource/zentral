import argparse
import json
import os
import sys


def build_probe(pack_filepath, probe_filepath, probe_actions):
    if os.path.exists(probe_filepath):
        raise ValueError('Probe file already exist')
    f = open(pack_filepath, 'r')
    pack_d = json.load(f)
    f.close()
    probe_d = {"name": os.path.basename(pack_filepath.rstrip('.conf')),
               "osquery": {"schedule": []},
               "actions": json.loads(probe_actions)}
    for q_name, q_conf in pack_d['queries'].items():
        value = q_conf.get("value", "")
        q_conf["value"] = "{}: {}".format(q_name, value)
        probe_d['osquery']['schedule'].append(q_conf)
    f = open(probe_filepath, 'w')
    json.dump(probe_d, f, indent=2)
    f.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Build a probe from a query pack')
    parser.add_argument('--pack', metavar='PCK', help="a query pack", required=True)
    parser.add_argument('--probe', metavar='PRB', help="a probe file", required=True)
    parser.add_argument('--actions', metavar='ACT', help="probe actions json cfg", required=True)
    args = parser.parse_args()
    build_probe(args.pack, args.probe, args.actions)
