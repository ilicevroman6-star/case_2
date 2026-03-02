import re

def find_and_validate_credit_cards(text):
    # Находит номера кредитных карт в тексте, проверяет их по алгоритму Луна
    # и возвращает словарь с валидными и невалидными картами.

    # Регулярное выражение для поиска 16 цифр, сгруппированных по 4,
    # между которыми могут быть пробелы или дефисы
    pattern = r'\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b'
    raw_matches = re.findall(pattern, text)

    # Очистка найденных номеров от пробелов и дефисов
    cards = []
    for card in raw_matches:
        clean_card = ''
        for ch in card:
            if ch.isdigit():
                clean_card += ch
        cards.append(clean_card)

    # Проверка по алгоритму Луна
    valid_cards = []
    invalid_cards = []

    for card in cards:
        # Алгоритм Луна
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
