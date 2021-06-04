def decode_args(s, delimiter="|", escapechar="\\"):
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
