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
