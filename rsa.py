import math
import sys

# Ensure stdout/stderr use UTF-8 so Unicode symbols (e.g. φ) print on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore
except Exception:
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ===============================
# PRIME CHECK (Optimized)
# ===============================
def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


# ===============================
# GCD FUNCTION
# ===============================
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


# ===============================
# EXTENDED EUCLIDEAN ALGORITHM
# ===============================
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


# ===============================
# MODULAR INVERSE
# ===============================
def mod_inverse(e, phi):
    gcd_val, x, y = extended_gcd(e, phi)
    if gcd_val != 1:
        return None
    return x % phi


# ===============================
# SAFE INTEGER INPUT
# ===============================
def safe_int_input(prompt):
    try:
        value = int(input(prompt))
        return value
    except ValueError:
        print("Invalid input. Must be an integer.")
        sys.exit()


def optional_int_input(prompt):
    """Read an integer from input, return None if the user submits a blank line."""
    s = input(prompt).strip()
    if s == "":
        return None
    try:
        return int(s)
    except ValueError:
        print("Invalid input. Must be an integer or blank for auto-select.")
        sys.exit()


# ===============================
# MAIN RSA PROGRAM
# ===============================
print("\n========== SECURE RSA IMPLEMENTATION ==========\n")

# --- Input primes ---
p = safe_int_input("Enter prime p: ")
q = safe_int_input("Enter prime q: ")

# Edge Case 1: Prime validation
if not is_prime(p):
    print(f"p = {p} is not prime. Please provide a prime number for p.")
    sys.exit()

if not is_prime(q):
    print(f"q = {q} is not prime. Please provide a prime number for q.")
    sys.exit()

if p == q:
    print("p and q must be different primes.")
    sys.exit()

# --- Compute n ---
n = p * q
print(f"\nStep 1: n = p × q = {n}")

if n <= 3:
    print("n too small. Choose larger primes.")
    sys.exit()

# --- Compute phi ---
phi = (p - 1) * (q - 1)
print(f"Step 2: φ(n) = (p-1)(q-1) = {phi}")

if phi <= 2:
    print(" φ(n) invalid.")
    sys.exit()

# --- Choose e ---
print("\nStep 3: Finding valid e values...")
valid_e = []

for i in range(2, phi):
    if gcd(i, phi) == 1:
        valid_e.append(i)

if not valid_e:
    print("No valid e found.")
    sys.exit()

print("Valid e values:", valid_e[:10], "...")  # Show first 10

# Read optional e: if blank, auto-select a safe default (prefer 65537)
user_e = optional_int_input("Choose e from valid values (leave blank to auto-select): ")
if user_e is None:
    # prefer common public exponent 65537 if valid and less than phi
    preferred = 65537
    if preferred < phi and gcd(preferred, phi) == 1:
        e = preferred
    else:
        # fall back to the smallest valid e
        e = valid_e[0]
    print(f"Auto-selected e = {e}")
else:
    e = user_e
    # Edge Case: e validation
    if e <= 1 or e >= phi:
        print("e must satisfy 1 < e < φ(n)")
        sys.exit()

    if gcd(e, phi) != 1:
        print("e is not coprime with φ(n)")
        sys.exit()

    print(f"Chosen e = {e}")

# --- Compute d ---
print("\nStep 4: Computing modular inverse of e...")

d = mod_inverse(e, phi)

if d is None:
    print("Modular inverse does not exist.")
    sys.exit()

print(f"d = {d}")

if (d * e) % phi != 1:
    print("Internal error: invalid modular inverse.")
    sys.exit()

# --- Display Keys ---
print("\nPUBLIC KEY  (e, n) =", (e, n))
print("PRIVATE KEY (d, n) =", (d, n))

# --- Message Input ---
message = safe_int_input("\nEnter message (integer < n): ")

# Edge Case: message validation
if message < 0:
    print("Message cannot be negative.")
    sys.exit()

if message >= n:
    print("Message must be less than n.")
    sys.exit()

if gcd(message, n) != 1:
    print("Warning: message not coprime with n (still decryptable but special case).")

# --- Encryption ---
print("\nStep 5: Encryption")
cipher = pow(message, e, n)
print(f"Cipher = {message}^{e} mod {n} = {cipher}")

if cipher == 0:
    print("Cipher is 0 (edge case).")

# --- Decryption ---
print("\nStep 6: Decryption")
decrypted = pow(cipher, d, n)
print(f"Decrypted = {cipher}^{d} mod {n} = {decrypted}")

# --- Final Verification ---
print("\n========== FINAL RESULT ==========")
print("Original Message :", message)
print("Encrypted Cipher :", cipher)
print("Decrypted Message:", decrypted)

if decrypted == message:
    print("SUCCESS: Decryption matches original message.")
else:
    print("ERROR: Decryption failed.")
