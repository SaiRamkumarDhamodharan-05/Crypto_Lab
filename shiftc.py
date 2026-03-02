print()
print("*** SHIFT CIPHER ***")
n=int(input("Enter the key value:"))
plain_text=input("Enter plain text:")
print("After encryption")
cipher_text=[chr((ord(char)+n-97)%26+97) if char.islower() else (chr((ord(char)+n-65)%26+65) if char.isupper() else char) for char in plain_text]
print("The cipher text is",''.join(cipher_text))
print("After Decryption")
decrypted_text=[chr((ord(char)-n-97)%26+97) if char.islower() else (chr((ord(char)-n-65)%26+65) if char.isupper() else char) for char in cipher_text]
print("The decrypted text is",''.join(decrypted_text))
print()