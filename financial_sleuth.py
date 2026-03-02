import re

# Функция проверки номера карты по алгоритму Луна
def luhn_check(card_number):
    clean_number = ''
    for ch in card_number:
        if ch.isdigit():
            clean_number = clean_number + ch
    if len(clean_number) != 16:
        return False
    reversed_digits = clean_number[::-1]
    total = 0
    for i in range(len(reversed_digits)):
        digit = int(reversed_digits[i])
        if i % 2 == 1:
            digit = digit * 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0

# Функция поиска номеров карт в тексте
def find_credit_cards(text):
    # Регулярное выражение ищет 16 цифр, сгруппированных по 4,
    # между которыми может быть пробел или дефис (или ничего)
    pattern = r'\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b'
    raw_matches = re.findall(pattern, text)
    clean_cards = []
    for card in raw_matches:
        clean_card = ''
        for ch in card:
            if ch.isdigit():
                clean_card += ch
        clean_cards.append(clean_card)
    return clean_cards

# Новая функция, которая возвращает словарь с валидными и невалидными картами
def find_and_validate_credit_cards(text):
    cards = find_credit_cards(text)
    valid_cards = []
    invalid_cards = []
    for card in cards:
        if luhn_check(card):
            valid_cards.append(card)
        else:
            invalid_cards.append(card)
    return {
        'cards': {'valid': valid_cards, 'invalid': invalid_cards}
    }

if __name__ == '__main__':
    with open('кейс2.txt', 'r', encoding='utf-8') as file:
        text = file.read()
    cards_dict = find_and_validate_credit_cards(text)
    print(cards_dict)
