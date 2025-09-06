import re
from rest_framework.exceptions import ValidationError

phone_regex = re.compile(r'^(?:\+998|998)(9[0-9]|33|88|50)[0-9]{7}$')
email_regex = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')


def chech_email_or_phone_number(user_input):
    if re.fullmatch(phone_regex, user_input):
        data = 'phone'
    elif re.fullmatch(email_regex, user_input):
        data = 'email'
    else:
        data = {
            'success': False,
            'msg': "Siz xato email yoki telefon raqam kiritdingiz!"
        }
        raise ValidationError(data)

    return data

print(chech_email_or_phone_number('oowr@gmail.com'))