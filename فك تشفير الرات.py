import base64, hashlib
from Crypto.Cipher import AES

mutex = "6q9BTQJNzGXCN8ZL"
h = hashlib.md5(mutex.encode()).digest()
key = h[:15] + h + b'\x00'

def dec(b64):
    return AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(b64)).decode().strip()

settings = {
    "Hosts":      "T5bRDN8c4qFQwXAWeRAajyQ1gKLs4ksZNWFzYjG6pTM=",
    "Port":       "7k1wmQpfVnqPH8wZku2a1g==",
    "KEY":        "7UUVTlecTb5LwmLgUuK05A==",
    "SPL":        "6b2BOgnb+mkyDpffu5q+Qw==",
    "Groub":      "liplGgyZkI2E9cYIKqYaEA==",
    "USBNM":      "WMRT9uTOMK1dV5PfyufJQg==",
    "InstallDir": "w2Kk1Ll1lAUzk79tfy8VMA==",
    "InstallStr": "j0N7KNhDRu892zyTO7AREQ==",
}
for k, v in settings.items():
    print(k, "=", dec(v))