import random # For genrating random numbers
from math import gcd # For GCD calculations
import math # For other math tools used

# Function to check if prime number or not
def is_prime(number):
    if number > 1: # If number is less than 2 then not considered prime number
        for i in range(2, int(math.sqrt(number)) + 1): # Iterate numbers from 2 and square roots them to find prime number
            if number % i == 0: # If divisible by any number then not considered prime and returns false
                return False
        return True # Else returns true

# Function to find next prime number greater than start
def find_next_prime(start):
    while not is_prime(start): # Next prime number cannot be the one before
        start += 1  # Should increment until prime number is found 
    return start # Return the start


# Extended Euclidean Algorithm to calculate the Modular Inverse (https://brilliant.org/wiki/extended-euclidean-algorithm/)
def modular_inverse(a, b):
    x = 0 # x coefficent
    y = 1 # y coefficent
    b0 = b # b0 is set to be equal to b to use later when returning the final answer in positive and not negative
    while a > 1: # Loop to reduce the number till GCD is equal to 1
        q = a // b # Calculate the quotient of a divided by b
        a, b = b, a % b # a will be set to current b and b to the remiander of a % b. These values will be updated as the iteration goes on
        x, y = y - q * x, x # x will be set to y - q * x and y is set to the previous x. This is to update the coefficents
    return y % b0 # Return the positive modulu inverse 


# Function to generate Private key
def generate_private_key(length=8, max_value=99): # Generate key of length of bits and max value of 1-99
    #print("\nGenerating private key.....")  # Debugging Comments
    e = [random.randint(1, max_value)] # Generates e values which are random numbers

    for int in range(1, length): # Iterates through the sequence each bit at a time
        e.append(sum(e) + random.randint(1, max_value)) # Generates random number based on the sum of previous iterations or bits
    #print("e values:", e) # Debuggin comments
    return e  # Returns e (Randome positive Integers)

# Function to generate Public key from Private key
def generate_public_key(e):
    q = find_next_prime(2 * sum(e))  # Add e values and multiply by 2 = eSum. Total value of eSum and he next sebsequent prime value above eSum
    #print("q values:", q) # Debuggin comments

    for w in range(2, q): # Loops through to find random number that has common factor with q
        if gcd(w, q) == 1: # GCD should be equal to 1 to be valid GCD
            break
    #print("w values:", w)  # Debuggin comments

    h = [(w * ei) % q for ei in e]   # To get h values iterate through e and multiply each value with w and mod with q to get ei
    #print("h values:", h) # Debugging comments
    return h, q, w   # Returns h (public key) q (prime number) and w (random number for GCD). e,q,w make up the private key and h is the public key

# Function to convert text binary to binary for encryption
def text_to_binary_values(text):
    binary_value_list = []  # Create a list for the text to binary conversion
    for char in text:  # Iterate through each character, converting it to binary
        binary_string_conversion = f"{ord(char):08b}"  # Convert each character to 8-bit binary
        binary_value_list.extend(int(bit) for bit in binary_string_conversion)  # Add each bit of the converted text string to the list as a integer (Not string)
    return binary_value_list  # Return the binary list


# Function to encrypt message using public key
def encrypt_message(binary_message, h):
    encrypted_text_list = []  # Create a ciphertext list to put the binary into
    for i in range(0, len(binary_message), 8): # Iterates through each bit of the message
        chunk = binary_message[i:i+8]  # Takes the first 8 bits (chunk) and start the encryption process, then the next 8 bits and so on...
        if len(chunk) < 8:  # Extra padding incase the bits are not a total of 8
            chunk += [0] * (8 - len(chunk))  # Add extra padding to the last x bits which are less than 8 (Just 0s at the end)
        encrypted_text = sum(mi * hi for mi, hi in zip(chunk, h)) # each h value is multiplied with a message bit to get encrypted weight and the total 8 bit encrypted weight is summed
        encrypted_text_list.append(encrypted_text) # Add this encrypted weight to ciphertext
        #print(f"Encrypted chunk: {chunk} -> Ciphertext weight: {encrypted_text}") # Debuggin comment
    return encrypted_text_list # Returns the list ciphertexts

# Function to decrypt the message using private key
def decrypt_message(encrypted_text_list, e, q, w): # To decrypt the message we need values e,q,w and W_inv which we will find
    w_inverse = modular_inverse(w, q) # Get the modular inverse of w which should be equivalant to 1
    #print(f"\nW_inv value: {w_inverse}") # Debuggin comments

    decrypted_binary = []  # Make a list for the decrypted binary
    for i, encrypted_text in enumerate(encrypted_text_list): # Iterate through each encrypted value within the ciphertext list
        c_prime = (encrypted_text * w_inverse) % q # Compute C' by multiplying ciphertext with w_inverse and mod q
        #print(f"c' value: {i + 1}: {c_prime}") # Debugging comment

        message = [] # Creates an empty list for each 8 bits (chunk) of the message to then decrypt it using the encrypted weight of each 8 bits of the mesage
        for ei in reversed(e): # Iterate over each value of the private key in reverse (starting with last e value which is the largest)
            bit = int(c_prime >= ei) # Compares c' value to each e value to get the bits that make up the original message
            message.insert(0, bit) # Insert the bit that was determined by comparision at the start (0 index right side) and go from there
            c_prime -= ei * bit # c' value is then calculted again to make sure it is updated according to bit returned through comparison (bit = 1 then c'- ei else c'). This ensure correct decryption progressively.
        decrypted_binary.extend(message) # Adds the bit to the message list created (8 bits at a time)
        #print(f"Decrypted chunk {i + 1}: {message}") # Debugging comment
    return decrypted_binary # Returns the decrypted text

# Function to convert decrypted binary to text
def binary_to_text_values(binary_message):
    text = "" # Empty string to store binary to text
    for i in range(0, len(binary_message), 8): # Iterate over the binary values 1 bit at a time
        binary_chunk = binary_message[i:i+8]  # Gets 8 bits at time (a chunk) and starts the binary to ASCII conversion
        char = chr(int(''.join(map(str, binary_chunk)), 2)) # The 8 bits then turns from Int (Base 2) to string characters. Then from Int to its ASCII value
        text += char # Add the characters to the text string 
    return text # Return the full text

if __name__ == "__main__":
    # User inputs message (Part 1)
    plaintext = input("Enter the text to encrypt: ")
    binary_message = text_to_binary_values(plaintext)
    #print("\nBinary conversion of the message:", binary_message) # Debuggin comment

    # Key generation (Step 1)
    e = generate_private_key()
    h, q, w = generate_public_key(e)

    #print("\nKeys Generated:") # Debuggin comment
    #print("-------------------------------------------------")
    #print("-------------------------------------------------")
    #print("Public Key (h):", h) # Debuggin comment
    #print("Private Key (e, q, w):", e, q, w) # Debuggin comment
    #print("-------------------------------------------------")
    #print("-------------------------------------------------")


    # Encryption (Step 2)
    encrypted_text_list = encrypt_message(binary_message, h)
    #print("\nEncrypted ciphertexts:", encrypted_text_list) # Debuggin comment

    # Decryption (Step 3)
    decrypted_binary = decrypt_message(encrypted_text_list, e, q, w)
    decrypted_binary = decrypted_binary[:len(binary_message)] # Removes the extra padding if given during encryption
    decrypted_text = binary_to_text_values(decrypted_binary)

    #print("\nDecrypted binary:", decrypted_binary) # Debuggin comment

    # Printing the decrypted text (Part 4)
    print("Decrypted binary to Text:", decrypted_text)


