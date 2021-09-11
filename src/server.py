import json
import logging
import os
import sys
from datetime import datetime

from aiohttp import web, BasicAuth, ClientSession
from aiojobs.aiohttp import setup, spawn
import dateutil.parser
from dateutil.tz import tzlocal
import jwt

from volgactf.final.checker.result import Result


logging.basicConfig(
    handlers=[logging.StreamHandler(sys.stdout)],
    level=logging.getLevelName(os.getenv('LOG_LEVEL', 'INFO'))
)
logger = logging.getLogger(__name__)

routes = web.RouteTableDef()

def import_path(filename):
    module = None
    directory, module_name = os.path.split(filename)
    module_name = os.path.splitext(module_name)[0]
    path = list(sys.path)
    sys.path.insert(0, directory)
    try:
        module = __import__(module_name)
    except Exception:
        logger.exception('An exception occurred', exc_info=sys.exc_info())
    finally:
        sys.path[:] = path  # restore
    return module


def load_checker():
    checker_module_name = os.getenv(
        'VOLGACTF_FINAL_CHECKER_MODULE',
        os.path.join(os.getcwd(), 'checker', 'main.py')
    )
    checker_module = import_path(checker_module_name)
    return checker_module


class CapsuleDecoder:
    def __init__(self):
        self.key = os.getenv(
            'VOLGACTF_FINAL_FLAG_SIGN_KEY_PUBLIC'
        ).replace('\\n', "\n")
        self.wrap_prefix_len = len(os.getenv('VOLGACTF_FINAL_FLAG_WRAP_PREFIX'))
        self.wrap_suffix_len = len(os.getenv('VOLGACTF_FINAL_FLAG_WRAP_SUFFIX'))

    def get_flag(self, capsule):
        payload = jwt.decode(
            capsule[self.wrap_prefix_len:-self.wrap_suffix_len],
            algorithms=['ES256', 'RS256'],
            key=self.key
        )
        return payload['flag']


class Metadata:
    def __init__(self, options):
        self._timestamp = options.get('timestamp', None)
        self._round = options.get('round', None)
        self._team_name = options.get('team_name', '')
        self._service_name = options.get('service_name', '')

    @property
    def timestamp(self):
        return self._timestamp

    @property
    def round(self):
        return self._round

    @property
    def team_name(self):
        return self._team_name

    @property
    def service_name(self):
        return self._service_name


checker = load_checker()
capsule_decoder = CapsuleDecoder()
master_auth = BasicAuth(
    login=os.getenv('VOLGACTF_FINAL_AUTH_MASTER_USERNAME'),
    password=os.getenv('VOLGACTF_FINAL_AUTH_MASTER_PASSWORD')
)


@web.middleware
async def basic_auth(request, handler):
    auth_header = request.headers.get('Authorization')
    authorized = False
    if auth_header:
        auth = BasicAuth.decode(auth_header)
        authorized = \
            auth.login == os.getenv('VOLGACTF_FINAL_AUTH_CHECKER_USERNAME') and\
            auth.password == os.getenv('VOLGACTF_FINAL_AUTH_CHECKER_PASSWORD')

    if not authorized:
        headers = {
            'WWW-Authenticate': 'Basic realm="{0}"'.format('Protected area')
        }
        return web.HTTPUnauthorized(headers=headers)

    return await handler(request)


async def safe_json_payload(request):
    payload = None
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        logger.error('Invalid payload', exc_info=sys.exc_info())
    finally:
        return payload


async def safe_push(endpoint, capsule, label, metadata):
    result = Result.INTERNAL_ERROR
    updated_label = label
    message = None
    try:
        raw_result = await checker.push(endpoint, capsule, label, metadata)
        if isinstance(raw_result, tuple):
            if len(raw_result) > 0:
                result = raw_result[0]
            if len(raw_result) > 1:
                updated_label = raw_result[1]
            if len(raw_result) > 2:
                message = raw_result[2]
        else:
            result = raw_result
    except Exception:
        logger.error('An exception occured', exc_info=sys.exc_info())
    return result, updated_label, message


async def handle_push(payload):
    params = payload['params']
    metadata = Metadata(payload['metadata'])
    t_created = dateutil.parser.parse(metadata.timestamp)
    t_delivered = datetime.now(tzlocal())

    flag = capsule_decoder.get_flag(params['capsule'])

    status, updated_label, message = await safe_push(
        params['endpoint'],
        params['capsule'],
        params['label'],
        metadata
    )

    t_processed = datetime.now(tzlocal())

    job_result = dict(
        status=status.value,
        flag=flag,
        label=updated_label,
        message=message
    )

    delivery_time = (t_delivered - t_created).total_seconds()
    processing_time = (
        t_processed - t_delivered
    ).total_seconds()

    log_message = ('PUSH flag `{0}` /{1:d} to `{2}`@`{3}` ({4}) - '
                   'status {5}, label `{6}` [delivery {7:.2f}s, '
                   'processing {8:.2f}s]').format(
        flag,
        metadata.round,
        metadata.service_name,
        metadata.team_name,
        params['endpoint'],
        status.name,
        job_result['label'],
        delivery_time,
        processing_time
    )

    logger.info(log_message)

    async with ClientSession(auth=master_auth) as session:
        uri = payload['report_url']
        async with session.post(uri, json=job_result) as r:
            if r.status != 204:
                logger.error(r.status)
                logger.error(await r.text())


@routes.post('/push')
async def push(request):
    payload = await safe_json_payload(request)
    if payload is None:
        return web.Response(status=400)
    await spawn(request, handle_push(payload))
    return web.Response(status=202)


async def safe_pull(endpoint, capsule, label, metadata):
    result = Result.INTERNAL_ERROR
    message = None
    try:
        raw_result = await checker.pull(endpoint, capsule, label, metadata)
        if isinstance(raw_result, tuple):
            if len(raw_result) > 0:
                result = raw_result[0]
            if len(raw_result) > 1:
                message = raw_result[1]
        else:
            result = raw_result
    except Exception:
        logger.exception('An exception occurred', exc_info=sys.exc_info())
    return result, message


async def handle_pull(payload):
    params = payload['params']
    metadata = Metadata(payload['metadata'])
    t_created = dateutil.parser.parse(metadata.timestamp)
    t_delivered = datetime.now(tzlocal())

    flag = capsule_decoder.get_flag(params['capsule'])

    status, message = await safe_pull(
        params['endpoint'],
        params['capsule'],
        params['label'],
        metadata
    )

    t_processed = datetime.now(tzlocal())

    job_result = dict(
        request_id=params['request_id'],
        status=status.value,
        message=message
    )

    delivery_time = (t_delivered - t_created).total_seconds()
    processing_time = (
        t_processed - t_delivered
    ).total_seconds()

    log_message = ('PULL flag `{0}` /{1:d} from `{2}`@`{3}` ({4}) with '
                   'label `{5}` - status {6} [delivery {7:.2f}s, '
                   'processing {8:.2f}s]').format(
        flag,
        metadata.round,
        metadata.service_name,
        metadata.team_name,
        params['endpoint'],
        params['label'],
        status.name,
        delivery_time,
        processing_time
    )

    logger.info(log_message)

    async with ClientSession(auth=master_auth) as session:
        uri = payload['report_url']
        async with session.post(uri, json=job_result) as r:
            if r.status != 204:
                logger.error(r.status)
                logger.error(await r.text())


@routes.post('/pull')
async def pull(request):
    payload = await safe_json_payload(request)
    if payload is None:
        return web.Response(status=400)
    await spawn(request, handle_pull(payload))
    return web.Response(status=202)


@routes.get('/healthcheck')
async def healthcheck(request):
    return web.Response(status=204)


def main():
    app = web.Application(middlewares=[basic_auth])
    app.add_routes(routes)
    setup(app)
    web.run_app(app, host='0.0.0.0', port=80)


if __name__ == '__main__':
    main()
