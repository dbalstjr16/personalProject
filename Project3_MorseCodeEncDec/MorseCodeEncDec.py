import sys

MORSE_CODE_DICT = {'A': '.-', 'B': '-...',
                   'C': '-.-.', 'D': '-..', 'E': '.',
                   'F': '..-.', 'G': '--.', 'H': '....',
                   'I': '..', 'J': '.---', 'K': '-.-',
                   'L': '.-..', 'M': '--', 'N': '-.',
                   'O': '---', 'P': '.--.', 'Q': '--.-',
                   'R': '.-.', 'S': '...', 'T': '-',
                   'U': '..-', 'V': '...-', 'W': '.--',
                   'X': '-..-', 'Y': '-.--', 'Z': '--..',
                   '1': '.----', '2': '..---', '3': '...--',
                   '4': '....-', '5': '.....', '6': '-....',
                   '7': '--...', '8': '---..', '9': '----.',
                   '0': '-----', ', ': '--..--', '.': '.-.-.-',
                   '?': '..--..', '/': '-..-.', '-': '-....-',
                   '(': '-.--.', ')': '-.--.-'}

reversed_MORSE_CODE_DICT = {morse_code: text_char for text_char, morse_code in MORSE_CODE_DICT.items()}


def encryption(message):
    message = message.upper()
    result = ''

    for char in message:
        if char not in MORSE_CODE_DICT:
            return -1
        result = result + MORSE_CODE_DICT.get(char)
        result = result + ' '

    return result


def decryption(ciphertext):
    current_letter = ''
    result = ''

    for i in range(len(ciphertext)):
        if ciphertext[i] != ' ':
            current_letter = current_letter + ciphertext[i]
        if ciphertext[i] == ' ' or i == len(ciphertext) - 1:
            if current_letter not in reversed_MORSE_CODE_DICT:
                return -1
            result = result + reversed_MORSE_CODE_DICT.get(current_letter)
            current_letter = ''

    return result


def main():
    encryptOrDecrypt = input('Would you like to encrypt or decrypt your message?\nPlease type "e" for encrypt or "d" for decrypt:\n')
    if encryptOrDecrypt == 'e':
        input_message = input('Enter a valid message to encrypt:\n')
        ciphertext = encryption(input_message)

        if ciphertext == -1:
            print('Not a valid message, please try again')
            sys.exit()

        print(f'Encrypted Message: {ciphertext}')

    elif encryptOrDecrypt == 'd':
        ciphertext = input('Enter a valid morse code to decrypt:\n')
        decrypted_message = decryption(ciphertext)

        if decrypted_message == -1:
            print('Not a valid morse code, please try again')
            sys.exit()

        print(f'Decrypted Message: {decrypted_message}')

    else:
        print('Not a valid option, please try again')
        sys.exit()

    print('Thank you for using Morse Code Encoder/Decoder!')


if __name__ == '__main__':
    main()
