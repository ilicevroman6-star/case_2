import re


def normalize_and_validate(text):
    """ Brings the data to a single format and verifies it
        Returns:  { 'phones': {'valid': [], 'invalid': []},
                    'dates': {'normalized': [], 'invalid': []},
                    'inn': {'valid': [], 'invalid': []},
                    'cards': {'valid': [], 'invalid': []} } """
    invalid_phones = []
    pattern_1 = r'[+]?[78][- ]?\d{3}[- ]?\d{3}[- ]?\d{2}[- ]?\d{2}'

    valid = re.findall(pattern_1, text)

    invalid_dates = []
    pattern_2 = r'(?:\d{2}[/.]\d{2}[/.]\d{2,4})|(?:\d{4}[/-]\d{2}[/-]\d{2})'
    normalized = re.findall(pattern_2, text)

    invalid_inn = []
    pattern_3 = r'(?:\b\d{10}\b)|(?:\b\d{12}\b)'
    valid_inn = re.findall(pattern_3, text)

    invalid_cards = []
    pattern_4 = r'\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}'
    valid_cards = set(re.findall(pattern_4, text))

    return {
        'phones': {'valid': valid, 'invalid': invalid_phones},
        'dates': {'normalized': normalized, 'invalid': invalid_dates},
        'inn': {'valid': valid_inn, 'invalid': invalid_inn},
        'cards': {'valid': valid_cards, 'invalid': invalid_cards}
           }


if __name__ == '__main__':
    with open('data_leak_sample.txt', 'r', encoding = 'utf-8') as file:
        data = file.read()
    result = normalize_and_validate(data)
    print(result)