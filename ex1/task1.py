import hashlib

def generate_sha256_hashes(start, end):
    # ハッシュ値を格納するための辞書
    hashes = {}


    target_hashes = "ee74f5e64c3a3ec88ccd793ff6ba1ebe1223ea1c9a3d455e85143d3f9c1b9751"

    # 指定された範囲の整数についてループ
    for number in range(start, end + 1):

        input_str = str(number)

        out_put = hashlib.sha256(input_str.encode('utf-8')).hexdigest()

        hashes[number] = out_put
        if out_put == target_hashes:
            print(input_str)
            print(out_put)
            break

    return hashes


hashes = generate_sha256_hashes(-9999, 9999)

# # 最初の5つの結果を出力して確認
# for key in sorted(hashes.keys())[:5]:
#     print(f"{key}: {hashes[key]}")
