#!/usr/bin/env python3
from base64 import b32encode, b32decode
from time import sleep
from io import BytesIO
from enum import Enum
import logging

from requests.exceptions import Timeout, ConnectionError
from dnslib import DNSRecord, DNSQuestion, QTYPE, DNSLabel
from PIL import Image
import requests

logger = logging.getLogger('DNSCaptcha.Client')
MAX_DOMAIN_NAME_LEN = 253
# NS = '212.2.96.51'  # aero2 ns1
NS = '212.2.96.52'  # aero2 ns2


API_KEY = 'ZTI2F'
D = 'io.juniorjpdj.pl'


class CaptchaStatus(Enum):
    FAILED = -1
    CREATED = 0
    UPLOADING = 1
    UPLOADED = 2
    RESOLVING = 3
    RESOLVED = 4
    VERIFIED = 5


class CaptchaDNSSender(object):
    def __init__(self, api_key, domain, ns, ns_port=53):
        self.api_key, self.domain, self.ns, self.ns_port = api_key, DNSLabel(domain), ns, ns_port

    def query(self, sub_domain):
        qname = self.domain.add(sub_domain)
        q = DNSRecord(q=DNSQuestion(qname=qname, qtype=QTYPE.CNAME))
        logger.debug('DNS Query:\n{q}'.format(q=q))
        rp = q.send(self.ns, self.ns_port)
        r = DNSRecord.parse(rp)
        logger.debug('DNS Response:\n{r}'.format(r=r))

        try:
            rr = r.rr[0].rdata.label.label
        except:
            rr = (b'error', b'client')
        return rr

    def upload_captcha(self, data):
        # partify data
        remaining_length = len(data)
        part_nr = -1
        parts = []
        while remaining_length > 0:
            part_nr += 1
            parts.append([])
            available_length = MAX_DOMAIN_NAME_LEN - len(self.domain.add('ul').add(self.api_key).add(5 * 'x').add(str(part_nr)))
            while available_length > 0:
                if available_length > 64:
                    data_len = 63
                    available_length -= 64
                else:
                    data_len = available_length - 1
                    available_length = 0
                parts[part_nr].append(data[:data_len])
                remaining_length -= data_len
                data = data[data_len:]

        # prepare data to send
        captcha_id = self.query(DNSLabel(b'new').add(self.api_key).add(str(len(parts))))[0]
        assert len(captcha_id) == 5 and captcha_id != b'error'

        # send data
        for part_nr in range(len(parts)):
            part = tuple(filter(None, parts[part_nr]))
            label = DNSLabel('ul').add(self.api_key).add(captcha_id).add(str(part_nr)).add(part)
            assert b'ok' == self.query(label)[0]

        return captcha_id

    def check_status(self, captcha_id):
        return CaptchaStatus[self.query(DNSLabel('st').add(self.api_key).add(captcha_id))[0].decode('ascii')]

    def get_captcha(self, captcha_id):
        return self.query(DNSLabel('get').add(self.api_key).add(captcha_id))[0]

    def mark_valid(self, captcha_id, valid):
        return self.query(DNSLabel('val').add(self.api_key).add(captcha_id).add('ok' if valid else 'bad'))[0] == b'ok'


class Captcha(object):
    def __init__(self):
        self.phpsessid = None
        self.img, self.comp_img = None, None

    def block_for_captcha(self):
        while True:
            try:
                data = requests.post('http://10.2.37.78:8080', {'viewForm': 'true'}, timeout=1)  # should timeout when no captcha
            except (Timeout, ConnectionError):
                sleep(0.5)
            else:
                self.phpsessid = data.text.split('name="PHPSESSID" value="')[1].split('"')[0]
                self.img = requests.get("http://10.2.37.78:8080/getCaptcha.html", {'PHPSESSID': self.phpsessid}).content
                compressed_captcha = BytesIO()
                Image.open(BytesIO(self.img)).convert('1').save(compressed_captcha, 'PNG')

                self.comp_img = compressed_captcha.getvalue()

                return self

    @property
    def b32_comp_img(self):
        assert self.comp_img is not None

        return b32encode(self.comp_img).rstrip(b'=')

    def send_response(self, response):
        assert self.phpsessid is not None

        post_data = {'PHPSESSID': self.phpsessid, 'viewForm': 'true', 'captcha': response}
        data = requests.post('http://10.2.37.78:8080', post_data, timeout=4)

        return "getCaptcha.html" not in data.text


if __name__ == "__main__":
    logging.basicConfig(format='[%(asctime)s][%(levelname)s] %(name)s: %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S',
                        level=logging.INFO)
    logging.getLogger('requests.packages.urllib3').setLevel(logging.WARNING)
    logger.info('Started')

    while True:
        sleep(3)
        c = Captcha().block_for_captcha()
        logger.info('Captcha detected and loaded, uploading')

        cds = CaptchaDNSSender(API_KEY, D, NS)
        cid = cds.upload_captcha(c.b32_comp_img)
        logger.info('Captcha uploaded, waiting for answer')

        while CaptchaStatus.FAILED.value < cds.check_status(cid).value < CaptchaStatus.RESOLVED.value:
            sleep(1)
        if cds.check_status(cid) == CaptchaStatus.FAILED:
            logger.info('Captcha resolve failed')
            continue
        logger.info('Captcha resolved, loading answer')

        data = cds.get_captcha(cid)
        data += (8 - len(data) % 8) % 8 * b'='  # restore padding
        ctxt = b32decode(data).decode('utf-8')
        logger.info('Captcha answer is {c}'.format(c=ctxt))

        ctxt_valid = c.send_response(ctxt)
        logger.info('Answer was {}valid, informing server'.format('' if ctxt_valid else 'not '))
        cds.mark_valid(cid, ctxt_valid)
        if ctxt_valid:
            sleep(120)
