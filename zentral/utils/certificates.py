def split_certificate_chain(filename):
    pem_certificates = []
    current_certificate = ""
    with open(filename, "r") as f:
        for line in f:
            if "--BEGIN" in line:
                if current_certificate:
                    pem_certificates.append(current_certificate)
                    current_certificate = ""
            current_certificate = "{}{}".format(current_certificate, line)
    if current_certificate:
        pem_certificates.append(current_certificate)
    return pem_certificates


def parse_dn(dn):
    # TODO: poor man's DN parser
    d = {}
    current_attr = ""
    current_val = ""

    state = "ATTR"
    string_state = "NOT_ESCAPED"
    for c in dn:
        if c == "\\" and string_state == "NOT_ESCAPED":
            string_state = "ESCAPED"
        else:
            if string_state == "NOT_ESCAPED" and c in "=,":
                if c == "=":
                    state = "VAL"
                elif c == ",":
                    state = "ATTR"
                    if current_attr:
                        d[current_attr] = current_val
                    current_attr = current_val = ""
            else:
                if state == "ATTR":
                    current_attr += c
                elif state == "VAL":
                    current_val += c
                if string_state == "ESCAPED":
                    string_state = "NOT_ESCAPED"

    if current_attr:
        d[current_attr] = current_val
        current_attr = current_val = ""
    return d
