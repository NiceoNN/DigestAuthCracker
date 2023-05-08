import re
from hashlib import sha256, md5

f_alg = {'MD5': md5, 'SHA-256': sha256}

def compute_digest(realm, username, password, nonce, uri, algorithm):
    f = f_alg[algorithm]
    a1 = f(f"{username}:{realm}:{password}".encode()).hexdigest()
    a2 = f(f"GET:{uri}".encode()).hexdigest()

    return f(f"{a1}:{nonce}:{a2}".encode()).hexdigest()

def parse_header(header):
    result = {}
    for key, value in re.findall(r'(\w+)="([^"]+)', header):
        result[key] = value

    return result

if __name__ == "__main__":
    header = 'Authorization: Digest username="test", realm="example", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", response="e80b5017098950fc58aad83c8c14978e", uri="/dir/index.html", algorithm="MD5"'

    parsed_header = parse_header(header)

    with open('top1kpassword.txt', 'r') as f:
        passwd = f.read().split('\n')

    for p in passwd:
        computed_response = compute_digest(parsed_header["realm"], parsed_header["username"], p, parsed_header["nonce"], parsed_header["uri"], parsed_header["algorithm"])
        if computed_response == parsed_header["response"]:
            print(f"Password found: {p}")
            break
        else:
            print(f"Trying password '{p}', computed response: {computed_response}")
    else:
        print("Password not found in the list.")



