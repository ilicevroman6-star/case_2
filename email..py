import re

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

    except FileNotFoundError:
        print(f"Ошибка: Файл '{filename}' не найден")
        return result
    except Exception as e:
        print(f"Ошибка: {e}")
        return result

result_1 = find_email_ip_file('program.txt')
print(result_1)