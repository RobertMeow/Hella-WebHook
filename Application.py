import os
import sys
import time
import logging

for module in ['vk_api', 'flask']:
    if module not in sys.modules:
        os.system('python3 -m pip install {} --user'.format(module))

from vk_api.longpoll import VkLongPoll
from vk_api.exceptions import Captcha, ApiError, AuthError
from vk_api import VkApi

from flask import Flask, request, jsonify

##################################################### -- <КОНФИГУРАЦИЯ>

TOKEN = ""  # Ваш токен VK Admin/Kate mobile
SECRET_KEY = ""  # Секретный ключ, из личных сообщений Хеллы

FORBIDDEN_METHODS = []  # Методы, которые запрещены для использования, например: ['account.getProfileInfo'], рекомендую оставить пустым для более стабильной работы.

LOGGING = False
##################################################### -- </КОНФИГУРАЦИЯ>

if LOGGING:
    logging.basicConfig(filename='logs.log', filemode='w', format='%(asctime)s | %(levelname)s -- %(message)s')


class ErrorCode:
    API = 1
    CAPTCHA = 2
    PYTHON = 3
    CAPTCHA = 4
    AUTH = 5
    INVALID_SECRET_KEY = 6
    METHOD_IS_PROHIBITED = 7


class HandlerHella(Flask):
    __slots__ = ['app', 'vk', 'lp']

    def __init__(self, import_name: str = __name__):
        self.app = super().__init__(import_name)
        self.vk = VkApi(token=TOKEN, api_version='5.141')
        self.lp = VkLongPoll(self.vk)
        self.add_url_rule('/WebHook/eventHandler', 'eventHandler', self.eventHandler, methods=['GET'])
        self.add_url_rule('/WebHook/vkMethod', 'APIHandler', self.APIHandler, methods=['POST'])
        self.add_url_rule('/WebHook/confirmationSecretKey', 'confirmation_secret_key', self.confirmation_secret_key, methods=['POST'])

    def get_events_vk(self):
        try:
            return [event.raw for event in self.lp.check()]
        except Captcha:
            return {"error": {"code": ErrorCode.CAPTCHA}}
        except AuthError:
            return {"error": {"code": ErrorCode.AUTH}}
        except ApiError:
            return {"error": {"code": ErrorCode.API}}
        except Exception as ex:
            return {"error": {"code": ErrorCode.PYTHON, 'desc': str(ex)}}

    def eventHandler(self):
        if request.args['secret_key'] != SECRET_KEY:
            return jsonify({"error": {"code": ErrorCode.INVALID_SECRET_KEY}})
        return jsonify({"date": time.time(), 'events': self.get_events_vk()})

    def APIHandler(self):
        if request.json['secret_key'] != SECRET_KEY:
            return jsonify({"error": {"code": ErrorCode.INVALID_SECRET_KEY}})
        if request.json['method'] in FORBIDDEN_METHODS:
            return jsonify({'error': {'code': ErrorCode.METHOD_IS_PROHIBITED}})
        try:
            return self.vk.method(request.json['method'], request.json['args'])
        except Captcha:
            return jsonify({"error": {"code": ErrorCode.CAPTCHA}})
        except ApiError:
            return jsonify({"error": {"code": ErrorCode.API}})
        except Exception as ex:
            return jsonify({"error": {"code": ErrorCode.PYTHON, 'desc': str(ex)}})

    @staticmethod
    def confirmation_secret_key():
        if request.json['secret_key'] != SECRET_KEY:
            return jsonify({"error": {"code": ErrorCode.INVALID_SECRET_KEY}})
        return jsonify({'success': 'ok'})


app = HandlerHella()
# app.run() # Убрать закраску (комментарий - #), если сервер pythonanywhere