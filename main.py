import argparse
from taxii2client.v21 import Server
from stix2.v21 import (ThreatActor, Identity, Relationship, Bundle)
from taxii2client.v21 import Collection, as_pages
from stix2 import parse
import json

__author__ = "Jesper Mikkelsen"
__version__ = "1.0.0"


def add_stuff(stix_bundle, collection_url, user, password):
    collection = Collection(collection_url, user=user, password=password)
    print(collection.title)
    collection.add_objects(stix_bundle, wait_for_completion=True)


def get_collection(id, user, password):
    collection = Collection(id, user=user, password=password)

    try:
        return json.dumps(collection.get_objects(), indent=4)
    except:
        return {}
        pass


def get(taxiiserver, user, password):
    server = Server(taxiiserver, user=user, password=password)

    api_root = server.api_roots
    for _a in api_root:
        try:
            for _b in _a.collections:

                print('CollectionID: {} : CollectionURL: {} : CollectionData: {}'.format(_b.id, _b.url, get_collection(_b.url, user, password)))
        except:
            pass


def put(stix_file, collection_url, user, password):
    file_handle = open(stix_file)
    obj = parse(file_handle, allow_custom=True)
    stix_boj = []
    for _o in obj['objects']:
        try:
            stix_boj.append(_o.serialize(pretty=True))
        except:
            pass
    bundle = Bundle(stix_boj, allow_custom=True)
    # print(bundle.serialize(pretty=True))
    add_stuff(bundle.serialize(pretty=True), collection_url, user, password)


if __name__ in '__main__':
    parser = argparse.ArgumentParser(
        prog='main.py',
        description=f'TAXII2 client. To post and get STIX data',
        epilog=f'Author: {__author__}'
    )
    parser.add_argument('--input', help='Input File', type=str, required=False)
    parser.add_argument('--user', help="user", type=str, default=True, required=False)
    parser.add_argument('--password', help='password', type=str, default=True, required=True)
    parser.add_argument('--command', help='put or get', type=str, default=True, required=True)
    parser.add_argument('--url', help='taxii-server', type=str, default=True, required=True)
    args = parser.parse_args()

    if args.command == 'put':
        put(args.input, args.url, args.user, args.password)
    elif args.command == 'get':
        get(args.url, args.user, args.password)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
