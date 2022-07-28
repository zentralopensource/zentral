def make_terraform_quoted_str(i):
    """make a Terraform quoted string literal from a python string"""
    o = ""
    escaped_c = None
    for c in i:
        if c == "{":
            if escaped_c:
                o += escaped_c * 2
                escaped_c = None
            o += c
        else:
            if escaped_c:
                o += escaped_c
                escaped_c = None
            if c in ("$", "%"):
                escaped_c = c
            elif c == "\n":
                o += "\\n"
            elif c == "\r":
                o += "\\r"
            elif c == "\t":
                o += "\\t"
            elif c == '"':
                o += '\\"'
            elif c == "\\":
                o += "\\\\"
            else:
                o += c
    if escaped_c:
        o += escaped_c
    return f'"{o}"'
