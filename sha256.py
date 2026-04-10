import struct

# ---------- Helper Functions ----------
def right_rotate(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


# ---------- SHA-256 Implementation ----------
def sha256(message):

    # =========================
    # Step 1: Padding
    # =========================
    message = bytearray(message, 'utf-8')
    original_length = len(message) * 8

    message.append(0x80)  # append '1' bit

    while ((len(message) * 8 + 64) % 512) != 0:
        message.append(0)

    message += struct.pack('>Q', original_length)


    # =========================
    # Step 3: Initialize Hash Values
    # =========================
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    # Round constants (64 values)
    K = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
        0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
        0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
        0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
        0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
        0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
        0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
        0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
        0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ]

    steps = {
        "initial_length": len(message) * 8 - 64,
        "padded_length": len(message) * 8,
        "initial_H": [f'{h:08x}' for h in H],
        "blocks": []
    }

    # =========================
    # Step 2: Divide into Blocks
    # =========================
    for block_num, i in enumerate(range(0, len(message), 64)):
        block = message[i:i+64]
        block_data = {}

        # Create message schedule
        W = list(struct.unpack('>16L', block)) + [0]*48
        block_data["W_initial"] = [f'{w:08x}' for w in W[:16]]

        for t in range(16, 64):
            s0 = right_rotate(W[t-15],7) ^ right_rotate(W[t-15],18) ^ (W[t-15] >> 3)
            s1 = right_rotate(W[t-2],17) ^ right_rotate(W[t-2],19) ^ (W[t-2] >> 10)
            W[t] = (W[t-16] + s0 + W[t-7] + s1) & 0xFFFFFFFF

        block_data["W_expanded"] = [f'{w:08x}' for w in W[16:24]]  # Show first 8 expanded

        # =========================
        # Step 4: Compression Function
        # =========================
        a, b, c, d, e, f, g, h = H
        block_data["rounds"] = []

        for t in range(64):
            S1 = right_rotate(e,6) ^ right_rotate(e,11) ^ right_rotate(e,25)
            ch = (e & f) ^ (~e & g)

            temp1 = (h + S1 + ch + K[t] + W[t]) & 0xFFFFFFFF

            S0 = right_rotate(a,2) ^ right_rotate(a,13) ^ right_rotate(a,22)
            maj = (a & b) ^ (a & c) ^ (b & c)

            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

            # Store first and every 8th round
            if t < 4 or t % 8 == 0:
                block_data["rounds"].append({
                    "round": t,
                    "a": f'{a:08x}', "b": f'{b:08x}', "c": f'{c:08x}', "d": f'{d:08x}',
                    "e": f'{e:08x}', "f": f'{f:08x}', "g": f'{g:08x}', "h": f'{h:08x}'
                })

        # Add compressed chunk to current hash value
        H = [(x+y) & 0xFFFFFFFF for x,y in zip(H, [a,b,c,d,e,f,g,h])]
        block_data["H_after"] = [f'{h:08x}' for h in H]
        
        steps["blocks"].append(block_data)

    # =========================
    # Step 5: Final Hash
    # =========================
    final_hash = ''.join(f'{value:08x}' for value in H)
    steps["final_hash"] = final_hash
    
    return final_hash, steps


# ----------- TEST -----------
if __name__ == "__main__":
    msg = input("Enter message: ")
    hash_val, steps = sha256(msg)
    print("SHA-256:", hash_val)
