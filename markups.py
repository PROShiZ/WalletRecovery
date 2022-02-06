from aiogram.types import KeyboardButton, ReplyKeyboardMarkup

info = KeyboardButton('📚 About project!')
manual = KeyboardButton('📜 Manuals!')
download = KeyboardButton('👀 Check log!')

mainMenu = ReplyKeyboardMarkup(resize_keyboard=True).add(download, manual, info)