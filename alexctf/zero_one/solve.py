import binascii
import base64

morseAlphabet = {'-..-': 'X',
                 '.----': '1',
                 '....': 'H',
                 '...--': '3',
                 '----.': '9',
                 '..-': 'U',
                 '.-..': 'L',
                 '...-': 'V',
                 '-.-': 'K',
                 '--.-': 'Q',
                 '.---': 'J',
                 '---': 'O',
                 '---..': '8',
                 '...': 'S',
                 '..-.': 'F',
                 '.--.': 'P',
                 '-..': 'D',
                 '-.--': 'Y',
                 '-.': 'N',
                 '.--': 'W',
                 '.-.': 'R',
                 '..': 'I',
                 '--.': 'G',
                 '.': 'E',
                 '-': 'T',
                 '..---': '2',
                 '-....': '6',
                 '.....': '5',
                 '-...': 'B',
                 '-.-.': 'C',
                 '.-': 'A',
                 '--': 'M',
                 '--...': '7',
                 '--..': 'Z',
                 '-----': '0',
                 '....-': '4'
                 }

with open("./zero_one", "r") as input_data:
    print("".join([morseAlphabet[c] for c in base64.b64decode(binascii.unhexlify(
        hex(int(input_data.read().replace("ZERO", "0").replace("ONE", "1").replace(" ", ""), 2))[2:])).decode().split(
        " ")]))
