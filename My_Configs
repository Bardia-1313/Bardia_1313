from warnings import filters
from telegram import updatez
from real_time_translator.translator import *
from real_time_translator.input_voice import transcript_from_file
from real_time_translator.input_image import imagetotext
from real_time_translator.languages import iso_639_choices
import telegram
from telegram.ext import Updater , CommandHandler, MessageHandler, Filters
import logging
import os

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                     level=logging.INFO)


updater = Updater(token='1931148200:AAFHmAmex9bn9BiwCshTyjBXWNGLUI9W5NM', use_context=True)
dispatcher = updater.dispatcher

def start(update, context):
    start_text='''
Welcome To Real Time Translator Bot
/help to Know how to use the Bot 
/language To change the language 
    
    '''
    context.bot.send_message(chat_id=update.effective_chat.id, text=start_text)

def help(update, context):
    help_text='''use /language + (The language Name)  to choose the language you want to translate to '''
    context.bot.send_message(chat_id=update.effective_chat.id, text=help_text)


to_lang=None

def language(update, context,args=None):
    print('In language')

    try:

        global to_lang
        to_lang=None
        lang_name = update.message.text.split()[1] # [1:] is to get rid of the / in id
        for lan in iso_639_choices :

            if lang_name.lower() ==lan[1].lower():
                context.bot.send_message(chat_id=update.effective_chat.id, text=f"Translate To {lang_name} ")
                to_lang=lan[0]

        if not to_lang:
            to_lang='en'
            context.bot.send_message(chat_id=update.effective_chat.id, text=f"Please Enter Correct Language Name, The Defult language is English ")   

        # [print (lans[0]) for lans in iso_639_choices if to_lang.lower() in lans[1].lower()]

    except:
        context.bot.send_message(chat_id=update.effective_chat.id, text=f"invald entart see /help")


def massage(update, context):
    print("inside massage ")

    # Deliver the translated massage
    context.bot.send_message(chat_id=update.effective_chat.id, text=translat_str(update.message.text,to_lang))

def audio(update,context):
    print("inside audio ")
    # context.bot.get_file(update.message.audio).download()


    # To Download the file to spesific Directory
    with open("assets/voices/file_0.mp3", 'wb') as f:
        context.bot.getFile(file_id=update.message.audio.file_id).download(out=f)
   
    # Deliver the translated massage
    path="assets/voices/file_0.mp3"
    context.bot.send_message(chat_id=update.effective_chat.id, text='Your Request under processing ')
    context.bot.send_message(chat_id=update.effective_chat.id, text=translat_str(transcript_from_file(path),to_lang))
    context.bot.send_message(chat_id=update.effective_chat.id, text='Done ')

    print("finished")


def image(update,context):
    print("inside image ")

    # To Download the file to spesific Directory
    with open("assets/images/file_0.jpg", 'wb') as f:
        context.bot.getFile(file_id=update.message.photo[-1].file_id).download(out=f)

    # Deliver the translated massage
    context.bot.send_message(chat_id=update.effective_chat.id, text='Your Request under processing ')
    context.bot.send_message(chat_id=update.effective_chat.id, text=translat_str(imagetotext('assets/images/file_0.jpg'),to_lang))
    context.bot.send_message(chat_id=update.effective_chat.id, text='Done ')

  
def recording(update,context):
    print("inside record")
    # context.bot.get_file(update.message.voice).download()

    # To Download the file to spesific Directory
    with open("assets/voices/file_1.oga", 'wb') as f:
        context.bot.getFile(file_id=update.message.voice.file_id).download(out=f)
    
    # Deliver the translated massage
    path="assets/voices/file_1.oga"
    context.bot.send_message(chat_id=update.effective_chat.id, text='Your Request under processing ')
    context.bot.send_message(chat_id=update.effective_chat.id, text=translat_str(transcript_from_file(path),to_lang))
    context.bot.send_message(chat_id=update.effective_chat.id, text='Done ')

    print("finished")


if not to_lang:
    to_lang="en"


if __name__ == '__main__':

    start_handler = CommandHandler('start', start)
    help_handler = CommandHandler('help', help)
    language_handler = CommandHandler('language', language,pass_args=True)
    massage_handler = MessageHandler(Filters.text & (~Filters.command), massage)
    audio_handler=MessageHandler(Filters.audio,audio)
    imag_handler=MessageHandler(Filters.photo,image)
    record_handler=MessageHandler(Filters.voice,recording)


    dr=dispatcher
    dr.add_handler(start_handler)
    dr.add_handler(help_handler)
    dr.add_handler(language_handler)
    dr.add_handler(massage_handler)
    dr.add_handler(audio_handler)
    dr.add_handler(imag_handler)
    dr.add_handler(record_handler)
    updater.start_polling()

# bot = telegram.Bot(token='1931148200:AAGK0N9WLdxD34WT71o2WIStSvQ2NW38LWU')
# print(bot.getUpdates()[0])
