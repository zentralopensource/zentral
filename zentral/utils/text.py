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
