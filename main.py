import re
import base64
import codecs


def decode_messages(file):
    """
    Finds and decrypts messages
    Returns: {'base64': [], 'hex': [], 'rot13': []}
    """

    mask_1 = r'[A-Za-z0-9+/]+[=]{1,2}'

    base64_strings = re.findall(mask_1, file)
    base64_decoded = []

    for message in base64_strings:
        base64message = base64.b64decode(message).decode('utf-8')
        base64_decoded.append(base64message)

    mask_2 = r'0x[A-Fa-f0-9]+'

    hex_strings = re.findall(mask_2, file)
    hex_decoded = []

    for message in hex_strings:
        hex_message = codecs.decode(message[2:], 'hex').decode('utf-8')
        hex_decoded.append(hex_message)

    # \s - находит и сохраняет при декодировании все пробельные символы
    mask_3 = r'\$[A-Za-z\s]+\$'

    rot13_strings = re.findall(mask_3, file)
    rot13_decoded = []

    for message in rot13_strings:
        rot13_message = codecs.decode(message, 'rot13')
        rot13_decoded.append(rot13_message.replace('$', ''))

    return {
        'base64': base64_decoded,
        'hex': hex_decoded,
        'rot13': rot13_decoded
           }


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


def secrets(file: str):
    """
    Function, searches for API keys, passwords, and access tokens in a text file.
    :param file: filename (str): path to the file to analyze
    :return: list: a list of found secrets (API keys)
    """

    try:
        with open(file, 'r') as f:
            text = f.read()

        # Search keys.
        regex_keys = r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{25,255}'
        keys = re.findall(regex_keys, text)

        # Search passwords.
        regex_passwords = r'[A-Za-z0-9!@#$%^&*()_+=\-]{8,}'
        maybe_passwords = re.findall(regex_passwords, text)

        passwords = []
        for element in maybe_passwords:
            # Check letters, numbers and special symbols.
            if (re.search(r'[A-Za-z]', element) and
                    re.search(r'[0-9]', element) and
                    re.search(r'[!@#$%^&*()_+\-=]', element)):

                # Excludes not passwords.
                if not re.search(r'\d{4}-\d{2}-\d{2}', element):
                    if not re.match(r'^(sk|pk|rk)_', element.lower()):
                        if element not in passwords:
                            passwords.append(element)

        return keys, passwords

    except FileNotFoundError:
        print(f'Ошибка: файл {file} не найден')
        return []



def find_email_ip_file(filename):
    '''
    Searches for system information and returns:
     {'ips': [], 'files': [], 'emails': []}
    '''

    result = {'ips': [], 'files': [], 'emails': []}

    try:
        with open(filename, 'r', encoding='utf-8') as file:
            text = file.read()

        email_regex = r'[\w.-]+@[\w.-]+\.\w+'
        result['emails'] = re.findall(email_regex, text)

        ip_regex = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        ip_candidates = re.findall(ip_regex, text)

        for ip in ip_candidates:
            number1, number2, number3, number4 = ip.split('.')
            number1 = int(number1)
            number2 = int(number2)
            number3 = int(number3)
            number4 = int(number4)
            if (number1 <= 255 and number2 <= 255 and
                number3 <= 255 and number4 <= 255):
                result['ips'].append(ip)

        file_regex = r'\b[\w.-]+\.(?:txt|log|ini|py|js)\b'
        result['files'] = re.findall(file_regex, text, re.IGNORECASE)  # Флаг, игнорирующий регистр

        return result
        
result_1 = find_email_ip_file('program.txt')
print(result_1)





def analyze_logs(file):
    """
    Function, searches for API keys, passwords, and access tokens in a text file.
    :param file: file (str): path to the file to analyze
    :return: list: a list of found secrets (API keys)
    """
    result = {
        'sql_injections': [],
        'xss_attacks': [],
        'suspicious_user_agents': [],
        'failed_logins': []
    }

    try:
        with open(file, 'r') as f:
            text = f.read()

        # Mask for SQL-injections.
        sql_mask = r'OR\s+.*?=.*?|UNION\s+SELECT|DROP\s+TABLE|--|;\s*$'

        # Mask for XSS-attack.
        xss_mask = r'<script.*?>.*?</script>|alert\s*\(|onerror\s*=|onload\s*='

        # Mask for suspicious User-Agents
        agent_mask = r'sqlmap|nikto|evilot|evilbot'

        # Mask for failed logins.
        login_mask = r'POST.*/login.*\s401|\s401\s|\s403\s'

        # Analysed every line
        for line in text.split('\n'):
            line = line.strip()
            if not line:
                continue

            # Check the SQL-injections
            if re.search(sql_mask, line, re.IGNORECASE):
                result['sql_injections'].append(line)

            # Check XSS-attack
            if re.search(xss_mask, line, re.IGNORECASE):
                result['xss_attacks'].append(line)

            #  Check suspicious User-Agent
            if re.search(agent_mask, line, re.IGNORECASE):
                result['suspicious_user_agents'].append(line)

            # Check failed logins
            if re.search(login_mask, line, re.IGNORECASE):
                result['failed_logins'].append(line)

        return result

    except FileNotFoundError:
        print(f"Error: file '{file}' not found")
        return result


result1 = secrets('example.txt')
result2 = analyze_logs('example.txt')
print(result1, result2, sep="\n")


def find_and_validate_credit_cards(text: str):
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


if __name__ == '__main__':
    try:
        with open('data_leak_sample_2.txt', 'r', encoding = 'utf-8') as f:
            text = f.read()
            result_1 = decode_messages(text)
            result_2 = normalize_and_validate(text)
            print(result_1)
            print(result_2)
    except FileNotFoundError:
        print('File not found')
        





