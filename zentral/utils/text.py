from hashlib import md5
import unicodedata


def str_to_ascii(value):
    return unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode('ascii')


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
    for version_elm in version.split("."):
        try:
            version_elm = "{:016d}".format(int(version_elm))
        except ValueError:
            pass
        sort_key.append(version_elm)
    return sort_key
