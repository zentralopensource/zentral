from hashlib import md5


def split_comma_separated_quoted_string(s):
    def iterator(s):
        current_word = []
        quote = False

        def flush(current_word):
            s = ("".join(current_word)).strip()
            for i in range(len(current_word)):
                current_word.pop()
            del current_word[:]
            return s
        for c in s:
            if c == '"':
                yield flush(current_word)
                quote = not quote
            elif c == ',':
                if quote:
                    current_word.append(c)
                else:
                    yield flush(current_word)
            else:
                current_word.append(c)
        yield flush(current_word)
    return list(w for w in iterator(s) if w)


def shard(key, salt="", modulo=100):
    if not isinstance(salt, str):
        salt = str(salt)
    return int(md5((key + salt).encode("utf-8")).hexdigest(), 16) % modulo


def get_version_sort_key(version):
    sort_key = []
    if not version or not isinstance(version, str):
        return sort_key
    for version_elm in version.split("."):
        try:
            version_elm = "{:016d}".format(int(version_elm))
        except ValueError:
            pass
        sort_key.append(version_elm)
    return sort_key


# encode / decode list of args with delimiter


def decode_args(s, delimiter="|", escapechar="\\"):
    assert delimiter != escapechar, "delimiter and escapechar must be different"
    args = []
    escaping = False
    current_arg = ""
    for c in s:
        if escaping:
            current_arg += c
            escaping = False
        elif c == escapechar:
            escaping = True
        elif c == delimiter:
            args.append(current_arg)
            current_arg = ""
        else:
            current_arg += c
    args.append(current_arg)
    return args


def encode_args(args, delimiter="|", escapechar="\\"):
    assert delimiter != escapechar, "delimiter and escapechar must be different"
    encoded_args = ""
    for idx, arg in enumerate(args):
        if idx > 0:
            encoded_args += delimiter
        if not isinstance(arg, str):
            arg = str(arg)
        for c in arg:
            if c == delimiter or c == escapechar:
                encoded_args += escapechar
            encoded_args += c
    return encoded_args
