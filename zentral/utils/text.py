import unicodedata


def str_to_ascii(value):
    return unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode('ascii')
