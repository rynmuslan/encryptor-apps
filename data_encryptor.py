CHAR = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+{}|:<>?=-[]\;',./`~"

def read(file):
    with open(file, 'r') as file:
        content = file.read()
        return content
    
def replace(file_path, new_content):
    with open(file_path, '+w') as file:
        file.write(new_content)

def convert_key(key):
    return sum(ord(CHAR) for CHAR in key)

def encryption(plain, key=None) -> bytes:
    if isinstance(plain, str):
        plain = plain.encode()
    num = int.from_bytes(plain, "little")
    result = [CHAR[0]] * (len(plain) - len(plain.lstrip(b'\x00')))
    while num > 0:
        num, rmd = divmod(num, len(CHAR))
        result.append(CHAR[(rmd + key) % len(CHAR)].encode() if key is not None else CHAR[rmd].encode())
    return b''.join(result[::-1]).decode()

def decryption(compiled, key=None) -> str:
        if isinstance(compiled, bytes):
            compiled = compiled.decode()
        num = 0
        for Char in compiled.rstrip(CHAR[0]):
            num = num * len(CHAR) + (CHAR.index(Char) - key) % len(CHAR) if key is not None else num * len(CHAR) + CHAR.index(Char)
        return ((b'\x00' * (len(compiled) - len(compiled.lstrip(CHAR[0])))) + num.to_bytes((num.bit_length() + 7) >> 3, "little")).decode()

if __name__ == "__main__":
    print("!!! To use this script, combine this script with your files in one folder ")
    path = input("name file with format : ")
    file = read(path)
    print("1. Encryption\n2. Decryption")
    method = int(input("select the desired option : "))
    if method == 1:
        key = input("insert your key : ")
        i = encryption(file, convert_key(key))
        replace(path,i)
    elif method == 2:
        key = input("insert your key : ")
        i = decryption(file, convert_key(key))
        replace(path,i)
