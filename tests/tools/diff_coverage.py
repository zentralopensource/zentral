#
# Tool to find all the python files in the project
# and compare the list with the list of files found
# by coverage in a .coverage sqlite3 database.
#
# Because we are using namespace packages, coverage is
# not able to find all the code, without adding some packages
# to the [coverage:run] source config in tox.ini. This tool
# helps make sure that all files are included in the report.
#
# First argument: the .coverage database
# Second argument: the root of the project
#
import os
import sqlite3


def get_coverage_files(coverage_db, prefix="/zentral/"):
    con = sqlite3.connect(coverage_db)
    cur = con.cursor()
    for row in cur.execute("select path from file;"):
        yield row[0].removeprefix(prefix)
    con.close()


def get_project_files(root):
    for root, dirs, files in os.walk(root):
        if not any(root.startswith(f"./{d}") for d in ("ee", "server", "zentral")):
            continue
        if root.endswith("__pycache__"):
            continue
        for name in files:
            if name.endswith(".py"):
                yield os.path.join(root[2:], name)


if __name__ == "__main__":
    import sys
    pfiles = set(get_project_files(sys.argv[2]))
    cfiles = set(get_coverage_files(sys.argv[1]))
    for rel_path in sorted(pfiles - cfiles):
        print("P", rel_path)
    for rel_path in sorted(cfiles - pfiles):
        print("C", rel_path)
