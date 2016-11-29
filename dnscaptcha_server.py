#!/usr/bin/env python3
from base64 import b32encode, b32decode, b64encode
from queue import Queue, Empty
from enum import Enum
import logging
import os

from dnslib import QTYPE, DNSRecord, RR, DNSLabel, A, NS, CNAME
from dnslib.server import BaseResolver, DNSServer, DNSLogger
from py9kw.py9kw import py9kw

logger = logging.getLogger('DNSCaptcha.Server')


PORT = 53
ADDR = '10.2.85.17'
# ADDR = '127.0.0.1'

D = 'io.juniorjpdj.pl'
NS_IP = '163.172.179.160'
NS_TTL = 60 * 60
ALLOWED_API_KEYS = [b'ZTI2F']


class Captcha(object):
    class Status(Enum):
        FAILED = -1
        CREATED = 0
        UPLOADING = 1
        UPLOADED = 2
        RESOLVING = 3
        RESOLVED = 4
        VERIFIED = 5

    def __init__(self, api_key, parts_num, queue):
        self.status, self.string, self.__parts = self.Status.CREATED, '', {}
        self.__api_key, self.__parts_num, self.queue = api_key, parts_num, queue
        self.__id = b32encode(os.urandom(3))[:5]
        self.__py9kw = py9kw(api_key)

    @property
    def id(self):
        return self.__id
    
    @property
    def str_id(self):
        return self.id.decode('ascii')

    @property
    def api_key(self):
        return self.__api_key

    @property
    def parts_num(self):
        return self.__parts_num

    def add_part(self, nr, data):
        assert 0 <= nr < self.parts_num
        assert nr not in self.__parts

        self.status = self.Status.UPLOADING
        self.__parts[nr] = data
        logger.info('Part {p} of captcha {c} uploaded'.format(p=nr, c=self.str_id))

        if self.parts_num == len(self.__parts):
            logger.info("All parts of captcha {c} are here, adding resolving to queue!".format(c=self.str_id))
            self.status = Captcha.Status.UPLOADED
            self.queue.put(self.resolve)

    def resolve(self):
        _9kw = self.__py9kw
        _9kw.uploadcaptcha(b64encode(self.get_captcha_img()), 180, 0)
        _9kw.sleep()
        _9kw.getresult()
        if _9kw.rslt[1]:
            self.string = _9kw.string
            self.status = self.Status.RESOLVED
            logger.info("Captcha {c} has been resolved ({r})!".format(c=self.str_id, r=self.string))
        else:
            self.status = self.Status.FAILED
            logger.info("Captcha {c} failed to resolve!".format(c=self.str_id))

    def check_uploaded(self):
        return self.status.value >= self.Status.UPLOADED.value and self.parts_num == len(self.__parts)

    def get_captcha_img(self):
        if self.check_uploaded():
            data = b''
            for i in range(self.parts_num):
                data += self.__parts[i]
            data += (8 - len(data) % 8) % 8 * b'='  # restore padding
            return b32decode(data)
        else:
            raise ValueError

    def get_enc_captcha(self):
        return b32encode(self.string.encode('utf-8')).rstrip(b'=')

    def mark_valid(self, valid):
        def mval(self, valid):
            logger.info('Captcha {c} was marked {v}valid'.format(c=self.str_id, v='' if valid else 'not '))
            self.__py9kw.captcha_correct(valid)

        self.queue.put(lambda: mval(self, valid))


class CaptchaDNSResolver(BaseResolver):
    def new_captcha(self, api_key, data):
        # parts.api_key
        try:
            assert len(data) >= 1
            parts = int(data[-1])
        except (ValueError, AssertionError):
            return 'error'
        else:
            while True:
                captcha = Captcha(api_key, parts, self.queue)
                if captcha.id not in self.captchas:
                    break
            self.captchas[captcha.id] = captcha
            logger.info('Added new captcha {id} in {p} part(s) to {a} api key'.format(a=api_key.decode('ascii'),
                                                                                      id=captcha.str_id,
                                                                                      p=parts))
            return captcha.id

    def uploading_captcha(self, api_key, data):
        # data.data...data.part_nr.captcha_id.api_key
        try:
            assert len(data) >= 3

            captcha_id = data[-1]
            assert captcha_id in self.captchas
            captcha = self.captchas[captcha_id]

            assert captcha.api_key == api_key

            part_nr = int(data[-2])
            part_data = b''.join(data[:-2])

            captcha.add_part(part_nr, part_data)

            return 'ok'
        except (ValueError, AssertionError):
            return 'error'

    def captcha_status(self, api_key, data):
        # captcha_id.api_key
        try:
            assert len(data) >= 1
            captcha_id = data[-1]

            assert captcha_id in self.captchas
            captcha = self.captchas[captcha_id]

            assert captcha.api_key == api_key
        except AssertionError:
            return 'error'
        else:
            return captcha.status.name

    def get_captcha(self, api_key, data):
        # captcha_id.api_key
        try:
            assert len(data) >= 1
            captcha_id = data[-1]

            assert captcha_id in self.captchas
            captcha = self.captchas[captcha_id]

            assert captcha.api_key == api_key

            assert captcha.status.value >= Captcha.Status.RESOLVED.value
        except AssertionError:
            return 'error'
        else:
            return DNSLabel('ok').add(captcha.get_enc_captcha())

    def captcha_valid(self, api_key, data):
        # ok/bad.captcha_id.api_key
        try:
            assert len(data) >= 2
            captcha_id = data[-1]
            valid = data[-2] == b'ok'

            assert captcha_id in self.captchas
            captcha = self.captchas[captcha_id]

            assert captcha.api_key == api_key

            assert captcha.status.value >= Captcha.Status.RESOLVED.value
        except AssertionError:
            return 'error'
        else:
            captcha.mark_valid(valid)
            del self.captchas[captcha.id]
            return 'ok'

    def __init__(self, domain, NS_IP, NS_TTL, allowed_api_keys, captcha_queue):
        self.D, self.ip, self.ttl = DNSLabel(domain), NS_IP, NS_TTL
        self.allowed_keys, self.queue = allowed_api_keys, captcha_queue
        self.OPERATIONS = {b'new': self.new_captcha, b'ul': self.uploading_captcha,
                           b'st': self.captcha_status, b'get': self.get_captcha,
                           b'val': self.captcha_valid}
        self.captchas = {}

    def resolve(self, request, handler):
        assert isinstance(request, DNSRecord)

        reply = request.reply()
        qname = request.q.qname
        D = self.D

        if request.q.qtype == QTYPE.NS and qname.matchSuffix(D):
            reply.add_answer(RR(rname=qname, rtype=QTYPE.NS, ttl=NS_TTL, rdata=NS(D.add('ns'))))
            reply.add_ar(RR(D.add('ns'), QTYPE.A, ttl=self.ttl, rdata=A(self.ip)))

        # valid queries: data.data...data.9kw_api_key.operation.rest of domain
        elif request.q.qtype == QTYPE.CNAME\
          and len(qname.label) >= (len(D.label) + 2)\
          and qname.label[-(len(D.label) + 1)] in self.OPERATIONS\
          and qname.label[-(len(D.label) + 2)] in self.allowed_keys:

            operation = qname.label[-(len(D.label) + 1)]
            api_key = qname.label[-(len(D.label) + 2)]
            data = qname.label[:-(len(D.label) + 2)]

            ret = self.OPERATIONS[operation](api_key, data)
            reply.add_answer(RR(qname, QTYPE.CNAME, ttl=0, rdata=CNAME(ret)))

        return reply

if __name__ == '__main__':
    logging.basicConfig(format='[%(asctime)s][%(levelname)s] %(name)s: %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S',
                        level=logging.INFO)
    logger.info('Started')

    captcha_queue = Queue()
    dns_resolver = CaptchaDNSResolver(D, NS_IP, NS_TTL, ALLOWED_API_KEYS, captcha_queue)

    udp_server = DNSServer(dns_resolver, port=PORT, address=ADDR, logger=DNSLogger('-request,-reply'))
    udp_server.start_thread()

    while udp_server.isAlive():
        try:
            f = captcha_queue.get(True, 0.2)
        except Empty:
            pass
        else:
            f()
