from flask import Flask, request, render_template, redirect, url_for, session
import subprocess
import math
from sha256 import sha256

app = Flask(__name__)
app.secret_key = "crypto_lab_secret_key"


def is_prime(n: int) -> bool:
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

@app.route("/", methods=["GET", "POST"])
def shift_cipher():
    output = ""
    error = ""
    
    # Read the code file
    with open("shiftc.py", "r", encoding="utf-8", errors="replace") as f:
        code = f.read()

    if request.method == "POST":
        try:
            key = request.form["key"]
            text = request.form["text"]
            
            # Store form values in session to preserve them after redirect
            session["shift_key"] = key
            session["shift_text"] = text

            process = subprocess.run(
                ["python", "shiftc.py"],
                input=f"{key}\n{text}\n",
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True
            )

            session["output"] = process.stdout
        except Exception as e:
            session["error"] = f"Error: {str(e)}"
        
        return redirect(url_for("shift_cipher"))
    
    # Get from session and clear
    output = session.pop("output", "")
    error = session.pop("error", "")
    key = session.pop("shift_key", "")
    text = session.pop("shift_text", "")

    return render_template("index.html", output=output, error=error, code=code, key=key, text=text)

@app.route("/hill", methods=["GET", "POST"])
def hill_cipher():
    output = ""
    error = ""
    
    # Read the code file
    with open("hillc.py", "r", encoding="utf-8", errors="replace") as f:
        code = f.read()

    if request.method == "POST":
        try:
            text = request.form["text"]
            keysize = request.form["keysize"]
            matrix = request.form["matrix"]
            
            # Store form values in session to preserve them after redirect
            session["hill_text"] = text
            session["hill_keysize"] = keysize
            session["hill_matrix"] = matrix
            
            # Clean up matrix input - remove extra whitespace and ensure proper formatting
            matrix_lines = [line.strip() for line in matrix.strip().split('\n') if line.strip()]
            matrix_formatted = '\n'.join(matrix_lines)
            
            # Format input for hillc.py: text, keysize, then matrix rows
            input_data = f"{text}\n{keysize}\n{matrix_formatted}\n"

            process = subprocess.run(
                ["python", "hillc.py"],
                input=input_data,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True
            )

            # Filter output to show only results
            full_output = process.stdout + process.stderr
            
            # Remove input prompts from output
            lines_to_remove = [
                "*** HILL CIPHER (ENCRYPTION + DECRYPTION) ***",
                "Enter the plain text:",
                "Enter key size n (e.g., 2 or 3):",
            ]
            filtered_lines = []
            for line in full_output.split('\n'):
                # Skip lines that are prompts or matrix input prompts
                if any(prompt in line for prompt in lines_to_remove):
                    continue
                if "matrix as key (each row space-separated):" in line:
                    continue
                filtered_lines.append(line)
            
            filtered_output = '\n'.join(filtered_lines).strip()
            
            session["hill_output"] = filtered_output
        except Exception as e:
            session["hill_error"] = f"Error: {str(e)}"
        
        return redirect(url_for("hill_cipher"))
    
    # Get from session and clear
    output = session.pop("hill_output", "")
    error = session.pop("hill_error", "")
    text = session.pop("hill_text", "")
    keysize = session.pop("hill_keysize", "")
    matrix = session.pop("hill_matrix", "")

    return render_template("hill.html", output=output, error=error, code=code, text=text, keysize=keysize, matrix=matrix)

@app.route("/playfair", methods=["GET", "POST"])
def playfair_cipher():
    output = ""
    error = ""
    
    # Read the code file
    with open("playfair.py", "r", encoding="utf-8", errors="replace") as f:
        code = f.read()

    if request.method == "POST":
        try:
            key = request.form["key"]
            text = request.form["text"]
            
            # Store form values in session to preserve them after redirect
            session["playfair_key"] = key
            session["playfair_text"] = text

            process = subprocess.run(
                 ["python", "playfair.py"],
                 input=f"{key}\n{text}\n",
                 text=True,
                 encoding="utf-8",
                 errors="replace",
                 capture_output=True
            )

            session["playfair_output"] = process.stdout
        except Exception as e:
            session["playfair_error"] = f"Error: {str(e)}"
        
        return redirect(url_for("playfair_cipher"))
    
    # Get from session and clear
    output = session.pop("playfair_output", "")
    error = session.pop("playfair_error", "")
    key = session.pop("playfair_key", "")
    text = session.pop("playfair_text", "")

    return render_template("playfair.html", output=output, error=error, code=code, key=key, text=text)

@app.route("/des", methods=["GET", "POST"])
def des_cipher():
    output = ""
    error = ""
    
    # Read the code file
    with open("des.py", "r", encoding="utf-8", errors="replace") as f:
        code = f.read()

    if request.method == "POST":
        try:
            plaintext = request.form["plaintext"]
            key = request.form["key"]
            
            # Store form values in session to preserve them after redirect
            session["des_plaintext"] = plaintext
            session["des_key"] = key
            
            # Validate hex input
            if len(plaintext) != 16 or not all(c in '0123456789ABCDEFabcdef' for c in plaintext):
                raise ValueError("Plaintext must be exactly 16 hex characters (64 bits)")
            if len(key) != 16 or not all(c in '0123456789ABCDEFabcdef' for c in key):
                raise ValueError("Key must be exactly 16 hex characters (64 bits)")

            process = subprocess.run(
                 ["python", "des.py"],
                 input=f"{plaintext}\n{key}\n",
                 text=True,
                 encoding="utf-8",
                 errors="replace",
                 capture_output=True
            )

            # Filter output to remove input prompts
            full_output = process.stdout + process.stderr
            lines_to_remove = [
                "Enter 64-bit Plaintext (HEX):",
                "Enter 64-bit Key (HEX):",
            ]
            filtered_lines = []
            for line in full_output.split('\n'):
                if any(prompt in line for prompt in lines_to_remove):
                    continue
                filtered_lines.append(line)
            
            filtered_output = '\n'.join(filtered_lines).strip()
            session["des_output"] = filtered_output
        except ValueError as e:
            session["des_error"] = f"Error: {str(e)}"
        except Exception as e:
            session["des_error"] = f"Error: {str(e)}"
        
        return redirect(url_for("des_cipher"))
    
    # Get from session and clear
    output = session.pop("des_output", "")
    error = session.pop("des_error", "")
    plaintext = session.pop("des_plaintext", "")
    key = session.pop("des_key", "")

    return render_template("des.html", output=output, error=error, code=code, plaintext=plaintext, key=key)

@app.route("/aes", methods=["GET", "POST"])
def aes_cipher():
    output = ""
    error = ""
    
    # Read the code file
    with open("aes.py", "r", encoding="utf-8", errors="replace") as f:
        code = f.read()

    if request.method == "POST":
        try:
            plaintext = request.form["plaintext"]
            key = request.form["key"]
            
            # Store form values in session to preserve them after redirect
            session["aes_plaintext"] = plaintext
            session["aes_key"] = key
            
            # Validate hex input
            if len(plaintext) != 32 or not all(c in '0123456789ABCDEFabcdef' for c in plaintext):
                raise ValueError("Plaintext must be exactly 32 hex characters (128 bits)")
            if len(key) != 32 or not all(c in '0123456789ABCDEFabcdef' for c in key):
                raise ValueError("Key must be exactly 32 hex characters (128 bits)")

            process = subprocess.run(
                 ["python", "aes.py"],
                 input=f"{plaintext}\n{key}\n",
                 text=True,
                 encoding="utf-8",
                 errors="replace",
                 capture_output=True
            )

            # Filter output to remove input prompts
            full_output = process.stdout + process.stderr
            lines_to_remove = [
                "Enter 128-bit Plaintext (HEX):",
                "Enter 128-bit Key (HEX):",
            ]
            filtered_lines = []
            for line in full_output.split('\n'):
                if any(prompt in line for prompt in lines_to_remove):
                    continue
                filtered_lines.append(line)
            
            filtered_output = '\n'.join(filtered_lines).strip()
            session["aes_output"] = filtered_output
        except ValueError as e:
            session["aes_error"] = f"Error: {str(e)}"
        except Exception as e:
            session["aes_error"] = f"Error: {str(e)}"
        
        return redirect(url_for("aes_cipher"))
    
    # Get from session and clear
    output = session.pop("aes_output", "")
    error = session.pop("aes_error", "")
    plaintext = session.pop("aes_plaintext", "")
    key = session.pop("aes_key", "")

    return render_template("aes.html", output=output, error=error, code=code, plaintext=plaintext, key=key)

@app.route("/rsa", methods=["GET", "POST"])
def rsa_cipher():
    output = ""
    error = ""
    # Read the code file
    with open("rsa.py", "r", encoding="utf-8", errors="replace") as f:
        code = f.read()

    if request.method == "POST":
        try:
            p = request.form["p"].strip()
            q = request.form["q"].strip()
            e = request.form.get("e", "").strip()
            message = request.form["message"].strip()

            # Validate integers and primality server-side so UI shows errors immediately
            try:
                p_int = int(p)
                q_int = int(q)
            except ValueError:
                session["rsa_error"] = "Error: p and q must be integers."
                return redirect(url_for("rsa_cipher"))

            if not is_prime(p_int):
                session["rsa_error"] = f"Error: p = {p_int} is not prime."
                return redirect(url_for("rsa_cipher"))
            if not is_prime(q_int):
                session["rsa_error"] = f"Error: q = {q_int} is not prime."
                return redirect(url_for("rsa_cipher"))
            if p_int == q_int:
                session["rsa_error"] = "Error: p and q must be different primes."
                return redirect(url_for("rsa_cipher"))  

            # Preserve values in session
            session["rsa_p"] = p
            session["rsa_q"] = q
            session["rsa_e"] = e
            session["rsa_message"] = message

            # Require e and validate it server-side against phi before running rsa.py
            if not e:
                session["rsa_error"] = "Error: e is required. Provide integer e satisfying 1 < e < φ(n) and gcd(e, φ(n)) = 1."
                return redirect(url_for("rsa_cipher"))

            try:
                e_int = int(e)
            except ValueError:
                session["rsa_error"] = "Error: e must be an integer."
                return redirect(url_for("rsa_cipher"))

            phi = (p_int - 1) * (q_int - 1)
            # Range check with detail
            if not (1 < e_int < phi):
                session["rsa_error"] = f"Error: e={e_int} is out of valid range. Required: 1 < e < φ(n)={phi}."
                return redirect(url_for("rsa_cipher"))

            # Coprimality check with gcd detail
            g = math.gcd(e_int, phi)
            if g != 1:
                session["rsa_error"] = (
                    f"Error: e={e_int} is not coprime with φ(n)={phi}. "
                    f"gcd(e, φ(n)) = {g}. Choose an e where gcd(e, φ(n)) = 1 (e.g., 3, 5, 17, 65537 if valid)."
                )
                return redirect(url_for("rsa_cipher"))

            # Prepare inputs for rsa.py (it expects p, q, e, message in sequence)
            # If e is empty, send a blank line so rsa.py can auto-select; otherwise send the provided e.
            input_data = f"{p}\n{q}\n{e}\n{message}\n"

            process = subprocess.run(
                 ["python", "rsa.py"],
                 input=input_data,
                 text=True,
                 encoding="utf-8",
                 errors="replace",
                 capture_output=True
            )

            # Filter out input prompts from output
            full_output = process.stdout + process.stderr
            lines_to_remove = [
                "Enter prime p:",
                "Enter prime q:",
                "Choose e from valid values:",
                "Enter message (integer < n):",
            ]
            filtered_lines = []
            for line in full_output.split('\n'):
                if any(prompt in line for prompt in lines_to_remove):
                    continue
                filtered_lines.append(line)

            filtered_output = '\n'.join(filtered_lines).strip()
            session["rsa_output"] = filtered_output
        except Exception as exc:
            session["rsa_error"] = f"Error: {str(exc)}"

        return redirect(url_for("rsa_cipher"))

    # Get from session and clear
    output = session.pop("rsa_output", "")
    error = session.pop("rsa_error", "")
    p = session.pop("rsa_p", "")
    q = session.pop("rsa_q", "")
    e = session.pop("rsa_e", "")
    message = session.pop("rsa_message", "")

    return render_template("rsa.html", output=output, error=error, code=code, p=p, q=q, e=e, message=message)


@app.route("/diffie", methods=["GET", "POST"])
def diffie_hellman():
    output = ""
    error = ""

    # Read the code file
    with open("diffie.py", "r", encoding="utf-8", errors="replace") as f:
        code = f.read()

    if request.method == "POST":
        try:
            p = request.form["p"].strip()
            g = request.form["g"].strip()
            a = request.form["a"].strip()
            b = request.form["b"].strip()

            # Preserve form values after redirect
            session["diffie_p"] = p
            session["diffie_g"] = g
            session["diffie_a"] = a
            session["diffie_b"] = b

            # Basic validation before running the script
            p_int = int(p)
            g_int = int(g)
            a_int = int(a)
            b_int = int(b)

            if p_int <= 2:
                raise ValueError("p must be greater than 2.")
            if not is_prime(p_int):
                raise ValueError(f"p = {p_int} must be prime.")
            if g_int <= 1 or g_int >= p_int:
                raise ValueError("g must satisfy 1 < g < p.")
            if a_int <= 0 or b_int <= 0:
                raise ValueError("Private keys a and b must be positive integers.")

            process = subprocess.run(
                ["python", "diffie.py"],
                input=f"{p}\n{g}\n{a}\n{b}\n",
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True
            )

            full_output = process.stdout + process.stderr
            # Remove interactive prompts for cleaner UI output.
            prompt_tokens = [
                "Enter prime number p:",
                "Enter base g:",
                "Enter Alice private key a:",
                "Enter Bob private key b:",
                "=== Diffie-Hellman Key Exchange (With Steps) ===",
            ]
            filtered_output = full_output
            for token in prompt_tokens:
                filtered_output = filtered_output.replace(token, "")

            session["diffie_output"] = filtered_output.strip()
        except ValueError as e:
            session["diffie_error"] = f"Error: {str(e)}"
        except Exception as e:
            session["diffie_error"] = f"Error: {str(e)}"

        return redirect(url_for("diffie_hellman"))

    # Get from session and clear
    output = session.pop("diffie_output", "")
    error = session.pop("diffie_error", "")
    p = session.pop("diffie_p", "")
    g = session.pop("diffie_g", "")
    a = session.pop("diffie_a", "")
    b = session.pop("diffie_b", "")

    return render_template("diffie.html", output=output, error=error, code=code, p=p, g=g, a=a, b=b)


@app.route("/primality", methods=["GET", "POST"])
def primality_test():
    output = ""
    error = ""
    
    # Read the code file
    with open("primality_test.py", "r", encoding="utf-8", errors="replace") as f:
        code = f.read()

    if request.method == "POST":
        try:
            number = request.form["number"]
            method = request.form["method"]
            
            # Store form values in session to preserve them after redirect
            session["primality_number"] = number
            session["primality_method"] = method
            
            # Validate input
            num = int(number)
            if num < 1:
                raise ValueError("Please enter a positive integer.")

            process = subprocess.run(
                 ["python", "primality_test.py"],
                 input=f"{number}\n{method}\n",
                 text=True,
                 encoding="utf-8",
                 errors="replace",
                 capture_output=True
            )

            # Filter output to remove input prompts
            full_output = process.stdout + process.stderr
            lines_to_remove = [
                "Enter number to test primality:",
                "Choose Method:",
                "1. Euclidean Method",
                "2. Fermat Test",
                "3. Miller–Rabin Test",
                "Enter choice (1/2/3):",
            ]
            filtered_lines = []
            for line in full_output.split('\n'):
                if any(prompt in line for prompt in lines_to_remove):
                    continue
                filtered_lines.append(line)
            
            filtered_output = '\n'.join(filtered_lines).strip()
            session["primality_output"] = filtered_output
        except ValueError as e:
            session["primality_error"] = f"Error: {str(e)}"
        except Exception as e:
            session["primality_error"] = f"Error: {str(e)}"
        
        return redirect(url_for("primality_test"))
    
    # Get from session and clear
    output = session.pop("primality_output", "")
    error = session.pop("primality_error", "")
    number = session.pop("primality_number", "")
    method = session.pop("primality_method", "1")

    return render_template("primality.html", output=output, error=error, code=code, number=number, method=method)

@app.route("/sha256", methods=["GET", "POST"])
def sha256_hash():
    output = ""
    error = ""
    message = ""
    input_length = ""
    steps_data = {}
    
    # Read the code file
    with open("sha256.py", "r", encoding="utf-8", errors="replace") as f:
        code = f.read()

    if request.method == "POST":
        try:
            message = request.form["message"]
            
            # Store form value in session to preserve it after redirect
            session["sha256_message"] = message
            
            # Calculate input length
            input_length = len(message) * 8
            
            # Generate hash
            hash_output, steps = sha256(message)
            
            session["sha256_output"] = hash_output
            session["sha256_input_length"] = input_length
            session["sha256_steps"] = steps
        except Exception as e:
            session["sha256_error"] = f"Error: {str(e)}"
        
        return redirect(url_for("sha256_hash"))
    
    # Get from session and clear
    output = session.pop("sha256_output", "")
    error = session.pop("sha256_error", "")
    message = session.pop("sha256_message", "")
    input_length = session.pop("sha256_input_length", "")
    steps_data = session.pop("sha256_steps", {})

    return render_template("sha256.html", output=output, error=error, code=code, message=message, input_length=input_length, steps=steps_data)

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
