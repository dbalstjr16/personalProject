import sys

# Morse code dictionary for encoding
MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
    'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
    'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
    'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
    'Z': '--..', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '0': '-----', ',': '--..--', '.': '.-.-.-', '?': '..--..', '/': '-..-.',
    '-': '-....-', '(': '-.--.', ')': '-.--.-', ' ': ' '
}

# Reversed Morse code dictionary for decoding
reversed_MORSE_CODE_DICT = {morse_code: text_char for text_char, morse_code in MORSE_CODE_DICT.items()}


def encryption(message):
    """Encrypts a plaintext message into Morse code."""
    message = message.upper()
    result = []

    for char in message:
        if char not in MORSE_CODE_DICT:
            raise ValueError(f"Invalid character '{char}' in message.")
        result.append(MORSE_CODE_DICT[char])

    return ' '.join(result)


def decryption(ciphertext):
    """Decrypts a Morse code message into plaintext."""
    words = ciphertext.strip().split('   ')  # Split Morse code into words
    result = []

    for word in words:
        letters = word.split(' ')  # Split word into letters
        decoded_word = []
        for letter in letters:
            if letter not in reversed_MORSE_CODE_DICT:
                raise ValueError(f"Invalid Morse code '{letter}' in ciphertext.")
            decoded_word.append(reversed_MORSE_CODE_DICT[letter])
        result.append(''.join(decoded_word))

    return ' '.join(result)


def main():
    """Main function to handle user input and run the program."""
    print("Welcome to the Morse Code Encoder/Decoder!")

    while True:
        encrypt_or_decrypt = input(
            'Would you like to encrypt or decrypt a message?\n'
            'Type "e" to encrypt, "d" to decrypt, or "q" to quit:\n'
        ).lower()

        if encrypt_or_decrypt == 'e':
            try:
                input_message = input('Enter a valid message to encrypt:\n')
                ciphertext = encryption(input_message)
                print(f'Encrypted Message: {ciphertext}')
            except ValueError as e:
                print(e)

        elif encrypt_or_decrypt == 'd':
            try:
                ciphertext = input(
                    'Enter a valid Morse code to decrypt (separate words with three spaces):\n'
                )
                decrypted_message = decryption(ciphertext)
                print(f'Decrypted Message: {decrypted_message}')
            except ValueError as e:
                print(e)

        elif encrypt_or_decrypt == 'q':
            print('Thank you for using the Morse Code Encoder/Decoder! Goodbye!')
            break

        else:
            print('Invalid option. Please enter "e", "d", or "q".')


if __name__ == '__main__':
    main()
