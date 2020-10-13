import zlib

KEYWORDS = {
    "ModelName": ("model_name", False),
    "ShortNickName": ("short_nick_name", False),
    "Manufacturer": ("manufacturer", False),
    "FileVersion": ("file_version", False),
    "Product": ("product", True),
    "PCFileName": ("pc_file_name", False),
}


def read_ppd_file(file_obj):
    content = file_obj.read()
    try:
        content = zlib.decompress(content, 16 + zlib.MAX_WBITS)
    except Exception:
        return content, False
    else:
        return content, True


def iter_ppd(content, encoding=None):
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(b"*%") or line == b"*End":
            # comment
            continue
        try:
            keyword, value = line.split(b" ", 1)
        except Exception:
            # strange line ?
            continue
        keyword = keyword.strip(b"*").strip(b":")
        value = value.strip().strip(b'"')
        if encoding:
            yield keyword.decode(encoding), value.decode(encoding)
        else:
            yield keyword, value


def get_ppd_information(file_obj):
    d = {}
    content, d["file_compressed"] = read_ppd_file(file_obj)
    encoding = None
    for keyword, value in iter_ppd(content):
        if keyword == b"LanguageEncoding":
            if value == b"ISOLatin1":
                encoding = "latin-1"
                break
            else:
                raise NotImplementedError("Unknown encoding type")
    for keyword, value in iter_ppd(content, encoding=encoding):
        try:
            attr, is_list = KEYWORDS[keyword]
        except KeyError:
            continue
        value = value.strip().strip('"')
        if is_list:
            d.setdefault(attr, []).append(value.strip("(").strip(")"))
        else:
            d[attr] = value
    return d


if __name__ == "__main__":
    import sys
    import pprint
    pprint.pprint(get_ppd_information(open(sys.argv[1], "rb")))
