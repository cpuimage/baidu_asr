# -*- coding:utf-8 -*-
from datetime import datetime
import base64
import hashlib
import hmac
import json
import sys
import time
import traceback
import wave
import requests

if sys.version_info.major == 2:
    from urllib import urlencode
    from urllib import quote
    from urlparse import urlparse
else:
    from urllib.parse import urlencode
    from urllib.parse import quote
    from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()


class BaiduAsr(object):
    __accessTokenUrl = 'https://aip.baidubce.com/oauth/2.0/token'

    __reportUrl = 'https://aip.baidubce.com/rpc/2.0/feedback/v1/report'

    __scope = 'brain_all_scope'

    def __init__(self):
        app_id = "填你自己的id"
        api_key = "填你自己的key"
        secret_key = "填你自己的secret_key"
        self._appId = app_id.strip()
        self._apiKey = api_key.strip()
        self._secretKey = secret_key.strip()
        self._authObj = {}
        self._isCloudUser = None
        self.__client = requests
        self.__connectTimeout = 60.0
        self.__socketTimeout = 60.0
        self._proxies = {}
        self.__version = '2_0_0'

    def get_version(self):
        """
            version
        """
        return self.__version

    def set_connection_timeout_in_millis(self, ms):
        """
            setConnectionTimeoutInMillis
        """

        self.__connectTimeout = ms / 1000.0

    def set_socket_timeout_in_millis(self, ms):
        """
            setSocketTimeoutInMillis
        """

        self.__socketTimeout = ms / 1000.0

    def set_proxies(self, proxies):
        """
            proxies
        """

        self._proxies = proxies

    def _request(self, url, data, headers=None):
        """
            self._request('', {})
        """
        try:
            res = self._validate()
            if not res:
                return res

            auth_obj = self._auth()
            params = self._get_params(auth_obj)

            data = self._proccess_request(url, params, data)
            headers = self._get_auth_headers('POST', url, params, headers)
            response = self.__client.post(url, data=data, params=params,
                                          headers=headers, verify=False,
                                          timeout=(self.__connectTimeout, self.__socketTimeout,), proxies=self._proxies
                                          )
            obj = self._proccess_result(response.content)

            if not self._isCloudUser and obj.get('error_code', '') == 110:
                auth_obj = self._auth(True)
                params = self._get_params(auth_obj)
                response = self.__client.post(url, data=data, params=params,
                                              headers=headers, verify=False,
                                              timeout=(self.__connectTimeout, self.__socketTimeout,),
                                              proxies=self._proxies
                                              )
                obj = self._proccess_result(response.content)
        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectTimeout):
            return {
                'error_code': 'SDK108',
                'error_msg': 'connection or read data timeout',
            }

        return obj

    @staticmethod
    def _validate():
        """
            validate
        """

        return True

    @staticmethod
    def _proccess_result(content):
        """
            formate result
        """

        if sys.version_info.major == 2:
            return json.loads(content) or {}
        else:
            return json.loads(content.decode()) or {}

    def _auth(self, refresh=False):
        """
            api access auth
        """

        # 未过期
        if not refresh:
            tm = self._authObj.get('time', 0) + int(self._authObj.get('expires_in', 0)) - 30
            if tm > int(time.time()):
                return self._authObj

        obj = self.__client.get(self.__accessTokenUrl, verify=False, params={
            'grant_type': 'client_credentials',
            'client_id': self._apiKey,
            'client_secret': self._secretKey,
        }, timeout=(
            self.__connectTimeout,
            self.__socketTimeout,
        ), proxies=self._proxies).json()

        self._isCloudUser = not self._is_permission()
        obj['time'] = int(time.time())
        self._authObj = obj

        return obj

    def _get_params(self, auth_obj):
        """
            api request http url params
        """

        params = {}

        if not self._isCloudUser:
            params['access_token'] = auth_obj['access_token']

        return params

    def _get_auth_headers(self, method, url, params=None, headers=None):
        """
            api request http headers
        """

        headers = headers or {}
        params = params or {}

        if not self._isCloudUser:
            return headers

        url_result = urlparse(url)
        for kv in url_result.query.strip().split('&'):
            if kv:
                k, v = kv.split('=')
                params[k] = v

        # UTC timestamp
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        headers['Host'] = url_result.hostname
        headers['x-bce-date'] = timestamp
        version, expire = '1', '1800'

        # 1 Generate SigningKey
        val = "bce-auth-v%s/%s/%s/%s" % (version, self._apiKey, timestamp, expire)
        signing_key = hmac.new(self._secretKey.encode('utf-8'), val.encode('utf-8'), hashlib.sha256).hexdigest()

        # 2 Generate CanonicalRequest
        # 2.1 Genrate CanonicalURI
        canonical_uri = quote(url_result.path)
        # 2.2 Generate CanonicalURI: not used here
        # 2.3 Generate CanonicalHeaders: only include host here

        canonical_headers = []
        for header, val in headers.items():
            canonical_headers.append(
                '%s:%s' % (
                    quote(header.strip(), '').lower(),
                    quote(val.strip(), '')
                )
            )
        canonical_headers = '\n'.join(sorted(canonical_headers))

        # 2.4 Generate CanonicalRequest
        canonical_request = '%s\n%s\n%s\n%s' % (
            method.upper(),
            canonical_uri,
            '&'.join(sorted(urlencode(params).split('&'))),
            canonical_headers
        )

        # 3 Generate Final Signature
        signature = hmac.new(signing_key.encode('utf-8'), canonical_request.encode('utf-8'),
                             hashlib.sha256
                             ).hexdigest()

        headers['authorization'] = 'bce-auth-v%s/%s/%s/%s/%s/%s' % (
            version,
            self._apiKey,
            timestamp,
            expire,
            ';'.join(headers.keys()).lower(),
            signature
        )

        return headers

    def report(self, feedback):
        """
            数据反馈
        """

        data = {'feedback': feedback}

        return self._request(self.__reportUrl, data)

    __asrUrl = 'http://vop.baidu.com/server_api'

    @staticmethod
    def _is_permission():
        """
            check whether permission
        """

        return True

    def _proccess_request(self, url, params, data):
        """
            参数处理
        """

        token = params.get('access_token', '')

        if not data.get('cuid', ''):
            data['cuid'] = hashlib.md5(token.encode()).hexdigest()

        if url == self.__asrUrl:
            data['token'] = token
            data = json.dumps(data)
        else:
            data['tok'] = token

        if 'access_token' in params:
            del params['access_token']

        return data

    def asr(self, speech=None, audio_format='pcm', rate=16000, options=None):
        """
            语音识别
        """

        data = {}

        if speech:
            data['speech'] = base64.b64encode(speech).decode()
            data['len'] = len(speech)

        data['channel'] = 1
        data['format'] = audio_format
        data['rate'] = rate

        data = dict(data, **(options or {}))

        return self._request(self.__asrUrl, data)

    def asr_file(self, wav_filepath):
        # 读取文件
        def get_wave_content(file_path):
            with wave.open(file_path, 'rb') as f:
                n = f.getnframes()
                cur_sample_rate = f.getframerate()
                cur_frames_data = f.readframes(n)
            return cur_frames_data, cur_sample_rate

        frames, sample_rate = get_wave_content(wav_filepath)
        return self.asr_buffer(frames, sample_rate)

    def asr_buffer(self, file_buffer, sample_rate):
        try:
            asr_result = self.asr(file_buffer, 'pcm', sample_rate, {'lan': 'zh', })
            if 'success' in asr_result['err_msg']:
                if asr_result['result'][0] == '':
                    return ""
                else:
                    return asr_result['result'][0]
            else:
                return "error:" + str(asr_result['err_no'])
        except Exception as e:
            print("baidu asr error: {}".format(traceback.format_exc()))
            return "error"


if __name__ == '__main__':
    input_path = sys.argv[1]
    asr = BaiduAsr()
    start_time = datetime.now()
    result = asr.asr_file(input_path)
    end_time = datetime.now()
    use_time = end_time - start_time
    print(result)
    print(use_time.total_seconds() * 1000, " ms")
