import re
import base64
import codecs

with open('data_leak_sample.txt', 'r', encoding = 'utf-8') as f:
    text = f.read()

def decode_messages(file):
    """
    Finds and decrypts messages
    Returns: {'base64': [], 'hex': [], 'rot13': []}
    """

    mask_1 = r'\b[A-Za-z0-9+/]+[=]{1,2}\b'

    text_no_spaces = file.replace(' ', '')
    base64_strings = re.findall(mask_1, text_no_spaces)
    base64_decoded = []

    for message in base64_strings:
        try:
            base64message = base64.b64decode(message).decode('utf-8')
            base64_decoded.append(base64message)
        except TypeError:
            print('Error decoding message')

    mask_2 = r'0x[A-Fa-f0-9]+'
    hex_strings = re.findall(mask_2, text_no_spaces)
    hex_decoded = []

    for message in hex_strings:
        try:
            hex_message = codecs.decode(message[2:], 'hex').decode('utf-8')
            hex_decoded.append(hex_message)
        except TypeError:
            print('Error decoding message')

    mask_3 = r'\$[A-Za-z]+\$'
    rot13_strings = re.findall(mask_3, text_no_spaces)
    rot13_decoded = []

    for message in rot13_strings:
        try:
            rot13_message = codecs.decode(message, 'rot13')
            rot13_decoded.append(rot13_message.replace('$', ''))
        except TypeError:
            print('Error decoding message')

    return base64_decoded, hex_decoded, rot13_decoded



result = decode_messages(text)
print(result)


