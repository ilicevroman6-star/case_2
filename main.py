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


