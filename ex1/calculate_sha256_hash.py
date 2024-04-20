import hashlib

input_str = "9448"
output = hashlib.sha256(input_str.encode('utf-8')).hexdigest()
print(output)
