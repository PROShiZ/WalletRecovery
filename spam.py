import requests

TOKEN = 'api telegram bot'

with open('guys.txt', 'r') as file:
    text = f'''
<b>🔥🔥🔥БОТ ОБНОВЛЁН!!🔥🔥🔥</b>
✍ Бот использует файлообменники - MEDIAFIRE и AnonFiles!
✍ Бот работает немного иначе изнутри!
✍ Бот подготовлен к глобальному переезду на другой анализатор найденных адрессов! И NFT токенов!\n
<b>ПСС... БРАТАН ИЛИ СЕСТРИЧКА:)</b>
Я трачу очень много времени для того чтобы сделать вам приятное и удобное пользование ботом и всё это <b>БЕСПЛАТНО</b>, не поленись пожалуйста, оставить отзыв на форуме)))

<b>Заранее спасибо)</b>
'''
    lines = file.readlines()
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    for line in lines:
        data = {
            'chat_id': f'{line[:-1]}',
            'text': f'{text}',
            'parse_mode': f'html'
        }
        requests.get(url, data=data)
