#!/usr/bin/env python3
import argparse
from datetime import datetime
import datetime
import jwt
from jwt.exceptions import InvalidSignatureError, InvalidTokenError, ExpiredSignatureError
import logging
import logging.config
import math
import os


LOG_LEVEL = os.getenv('LOG_LEVEL')
if not LOG_LEVEL:
    LOG_LEVEL = 'INFO'

logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'default': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        },
    },
    'handlers': {
        'default': {
            'formatter': 'default',
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',
        },
    },
    'loggers': {
        '': {
            'handlers': ['default'],
            'level': LOG_LEVEL,
        },
    },
})

logger = logging.getLogger(__name__)

logger = logging.getLogger('')
ALGORITHM = 'HS256'


def print_decoded(decoded):
    print(f'Payload fields decoded')
    for key,value in decoded.items():
        if key == 'exp':
            print(f"{key}: {datetime.date.fromtimestamp(decoded['exp'])}")
        else:
            print(f'{key}: {value}')


def generate_token(secret_key, args):
    payload = { 'sub': 'user',
                'email': 'provocamper@gmail.com',
                'exp': generate_expiration(days=90)
            }
    return jwt.encode(payload, secret_key, algorithm=ALGORITHM,
                      headers={"alg": ALGORITHM, "typ": "JWT" })


def generate_expiration(seconds=0, minutes=0, hours=0, days=0):
    expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=seconds,
                                                                                   minutes=minutes,
                                                                                   hours=hours,
                                                                                   days=days)
    return math.floor(expiration.timestamp())

def decode_token(in_token, secret_key, args):
    if not in_token:
        return ''
    decoded_token = ''
    try:
        decoded_token = jwt.decode(in_token, secret_key, algorithms=ALGORITHM)
    except ExpiredSignatureError as expired:
        logger.error(f'An ExpiredSignature error has been thrown {expired}')
        decoded_token = jwt.decode(in_token, secret_key, algorithms=ALGORITHM, options={'verify_exp': False})
        logging.error(decoded_token)
        if not args.renew:
            decoded_token = ''
    except InvalidTokenError as invalid:
        logger.error(f'An InvalidTokenError error has been thrown {invalid}')
        logger.error(jwt.decode(in_token, secret_key, algorithms=ALGORITHM))
    except InvalidSignatureError as signature:
        logger.error(f'An InvalidSignatureError error has been thrown {signature}')
        logger.error(jwt.decode(in_token, secret_key, algorithms=ALGORITHM))
    return decoded_token


def renew_expiration(decoded):
    decoded['exp'] = generate_expiration(days=90)
    if 'sub' not in decoded:
        decoded['sub'] = 'customer'
    return decoded


def encode_text(decoded, key: str):
    return jwt.encode(decoded, key, algorithm=ALGORITHM,
                      headers={"alg": ALGORITHM, })

def get_key(args_key):
    return os.getenv("IN_KEY", args_key)

def main():
    parser = argparse.ArgumentParser(description='renew a jwt token')
    parser.add_argument('--in', dest='in_token', type=str, help='Set the input token to be processed.')
    parser.add_argument('--key', dest='in_key', type=str, help='The key for decoding tokens')
    parser.add_argument('--renew', action='store_true', help='The key for decoding tokens')
    parser.add_argument('--encode', action='store_true', help='Encode the result')
    parser.add_argument('--print', action='store_true', help='The key for decoding tokens')
    parser.add_argument('--generate', action='store_true', help='Generate a token.')
    args = parser.parse_args()
    encoded_token = None
    if args.in_token:
        encoded_token = args.in_token
    elif args.generate:
        encoded_token = generate_token(get_key(args.in_key), args)

    decoded = decode_token(encoded_token, get_key(args.in_key), args)
    if not decoded:
        print(f'There was an error decoding the JWT exiting....')
        return

    if args.renew and not args.generate:
        decoded = renew_expiration(decoded)
    if args.encode:
        encoded_token = encode_text(decoded, get_key(args.in_key))

    if args.print:
        if decoded:
            print_decoded(decoded)
        if encoded_token:
            print(f'\n\n{encoded_token}\n\n')


if __name__ == "__main__":
    main()
