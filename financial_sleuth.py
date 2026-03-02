import re

def find_and_validate_credit_cards(text):
    # It finds credit card numbers in the text, checks them using the Luna algorithm,
    # and returns a dictionary with valid and invalid cards.

    # A regular expression for searching for 16 digits grouped into 4,
    # with spaces or hyphens between them.
    pattern = r'\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b'
    raw_matches = re.findall(pattern, text)

    # Cleaning found numbers from spaces and hyphens.
    cards = []
    for card in raw_matches:
        clean_card = ''
        for ch in card:
            if ch.isdigit():
                clean_card += ch
        cards.append(clean_card)

    # Verification using the Moon algorithm.
    valid_cards = []
    invalid_cards = []

    for card in cards:
        if len(card) != 16:
            invalid_cards.append(card)
            continue
        reversed_digits = card[::-1]
        total = 0
        for i in range(len(reversed_digits)):
            digit = int(reversed_digits[i])
            if i % 2 == 1:
                digit = digit * 2
                if digit > 9:
                    digit -= 9
            total += digit
        if total % 10 == 0:
            valid_cards.append(card)
        else:
            invalid_cards.append(card)

    return {'cards': {'valid': valid_cards, 'invalid': invalid_cards}}
