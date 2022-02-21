from pymongo import ASCENDING, IndexModel, MongoClient
import calendar
import datetime as dt
import threading
import uuid

import pytz
from six import iteritems


def create_resource(resource_name, items, more=False, next_id=None):
    """Generates a Resource Object given a resource name."""
    resource = {}
    if items:
        resource[resource_name] = items
    if resource_name == "objects" or resource_name == "versions":
        if next_id and resource:
            resource["next"] = next_id
        if resource:
            resource["more"] = more
    return resource


def determine_version(new_obj, request_time):
    """Grab the modified time if present, if not grab created time,
    if not grab request time provided by server."""
    return new_obj.get("modified", new_obj.get("created", datetime_to_string(request_time)))


def determine_spec_version(obj):
    """Given a STIX 2.x object, determine its spec version."""
    missing = ("created", "modified")
    if all(x not in obj for x in missing):
        # Special case: only SCOs are 2.1 objects and they don't have a spec_version
        # For now the only way to identify one is checking the created and modified
        # are both missing.
        return "2.1"
    return obj.get("spec_version", "2.0")


def get(data, key):
    """Given a dict, loop recursively over the object. Returns the value based on the key match"""
    for ancestors, item in iterpath(data):
        if key in ancestors:
            return item


def iterpath(obj, path=None):
    """
    Generator which walks the input ``obj`` model. Each iteration yields a
    tuple containing a list of ancestors and the property value.

    Args:
        obj: A SDO or SRO object.
        path: None, used recursively to store ancestors.

    Example:
        >>> for item in iterpath(obj):
        >>>     print(item)
        (['type'], 'campaign')
        ...
        (['cybox', 'objects', '[0]', 'hashes', 'sha1'], 'cac35ec206d868b7d7cb0b55f31d9425b075082b')

    Returns:
        tuple: Containing two items: a list of ancestors and the property value.

    """
    if path is None:
        path = []

    for varname, varobj in iter(sorted(iteritems(obj))):
        path.append(varname)
        yield (path, varobj)

        if isinstance(varobj, dict):

            for item in iterpath(varobj, path):
                yield item

        elif isinstance(varobj, list):

            for item in varobj:
                index = "[{0}]".format(varobj.index(item))
                path.append(index)

                yield (path, item)

                if isinstance(item, dict):
                    for descendant in iterpath(item, path):
                        yield descendant

                path.pop()

        path.pop()


def get_timestamp():
    """Get current time with UTC offset"""
    return dt.datetime.now(tz=pytz.UTC)


def datetime_to_string(dttm):
    """Given a datetime instance, produce the string representation
    with microsecond precision"""
    # 1. Convert to timezone-aware
    # 2. Convert to UTC
    # 3. Format in ISO format with microsecond precision

    if dttm.tzinfo is None or dttm.tzinfo.utcoffset(dttm) is None:
        # dttm is timezone-naive; assume UTC
        zoned = pytz.UTC.localize(dttm)
    else:
        zoned = dttm.astimezone(pytz.UTC)
    return zoned.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def datetime_to_string_stix(dttm):
    """Given a datetime instance, produce the string representation
    with millisecond precision"""
    # 1. Convert to timezone-aware
    # 2. Convert to UTC
    # 3. Format in ISO format with millisecond precision,
    #       except for objects defined with higher precision
    # 4. Add "Z"

    if dttm.tzinfo is None or dttm.tzinfo.utcoffset(dttm) is None:
        # dttm is timezone-naive; assume UTC
        zoned = pytz.UTC.localize(dttm)
    else:
        zoned = dttm.astimezone(pytz.UTC)
    ts = zoned.strftime("%Y-%m-%dT%H:%M:%S")
    ms = zoned.strftime("%f")
    if len(ms[3:].rstrip("0")) >= 1:
        ts = ts + "." + ms + "Z"
    else:
        ts = ts + "." + ms[:3] + "Z"
    return ts


def datetime_to_float(dttm):
    """Given a datetime instance, return its representation as a float"""
    # Based on this solution: https://stackoverflow.com/questions/30020988/python3-datetime-timestamp-in-python2
    if dttm.tzinfo is None:
        return calendar.timegm(dttm.utctimetuple()) + dttm.microsecond / 1e6
    else:
        return (dttm - dt.datetime(1970, 1, 1, tzinfo=pytz.UTC)).total_seconds()


def float_to_datetime(timestamp_float):
    """Given a floating-point number, produce a datetime instance"""
    return dt.datetime.utcfromtimestamp(timestamp_float)


def string_to_datetime(timestamp_string):
    """Convert string timestamp to datetime instance."""
    try:
        return dt.datetime.strptime(timestamp_string, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return dt.datetime.strptime(timestamp_string, "%Y-%m-%dT%H:%M:%SZ")


def generate_status(
    request_time, status, succeeded, failed, pending,
    successes=None, failures=None, pendings=None,
):
    """Generate Status Resource as defined in TAXII 2.1 section (4.3.1) <link here>`__."""
    status = {
        "id": str(uuid.uuid4()),
        "status": status,
        "request_timestamp": request_time,
        "total_count": succeeded + failed + pending,
        "success_count": succeeded,
        "failure_count": failed,
        "pending_count": pending,
    }

    if successes:
        status["successes"] = successes
    if failures:
        status["failures"] = failures
    if pendings:
        status["pendings"] = pendings

    return status


def generate_status_details(id, version, message=None):
    """Generate Status Details as defined in TAXII 2.1 section (4.3.1) <link here>`__."""
    status_details = {
        "id": id,
        "version": version
    }

    if message:
        status_details["message"] = message

    return status_details


def get_custom_headers(manifest_resource):
    """Generates the X-TAXII-Date-Added headers based on a manifest resource"""
    headers = {}

    times = sorted(map(lambda x: x["date_added"], manifest_resource.get("objects", [])))
    if len(times) > 0:
        headers["X-TAXII-Date-Added-First"] = times[0]
        headers["X-TAXII-Date-Added-Last"] = times[-1]

    return headers


def parse_request_parameters(filter_args):
    """Generates a dict with params received from client"""
    session_args = {}
    for key, value in filter_args.items():
        if key != "limit" and key != "next":
            session_args[key] = set(value.replace(" ", "").split(","))
    return session_args


def find_att(obj):
    """
    Used for finding the version attribute of an ambiguous object. Manifests
    use the "version" field, but objects will use "modified", or if that's not
    available, the "created" field.

    Args:
        obj (dict): manifest or stix object

    Returns:
        string value of the field from the object to use for versioning

    """
    if "version" in obj:
        return string_to_datetime(obj["version"])
    elif "modified" in obj:
        return string_to_datetime(obj["modified"])
    elif "created" in obj:
        return string_to_datetime(obj["created"])
    else:
        return string_to_datetime(obj["_date_added"])


def find_version_attribute(obj):
    """Depending on the object, modified, created or _date_added is used to store the
    object version"""
    if "modified" in obj:
        return "modified"
    elif "created" in obj:
        return "created"
    elif "_date_added" in obj:
        return "_date_added"


class SessionChecker(object):
    """Calls a target method every X seconds to perform a task."""

    def __init__(self, interval, target_function):
        self.interval = interval
        self.target_function = target_function
        self.thread = threading.Timer(interval=self.interval, function=self.handle_function)
        self.thread.daemon = True

    def handle_function(self):
        self.target_function()
        self.thread = threading.Timer(interval=self.interval, function=self.handle_function)
        self.thread.daemon = True
        self.thread.start()

    def start(self):
        self.thread.start()

#from medallion.common import datetime_to_float, string_to_datetime

MONGODB_URL = 'mongodb://taxiidb:MwSZboPcpKkQfN07@cluster0-shard-00-00.r7tjd.mongodb.net:27017,cluster0-shard-00-01.r7tjd.mongodb.net:27017,cluster0-shard-00-02.r7tjd.mongodb.net:27017/myFirstDatabase?ssl=true&replicaSet=atlas-7vk6bi-shard-0&authSource=admin&retryWrites=true&w=majority'

def connect_to_client(url=MONGODB_URL):
    """
    Fill:
        Connect to a mongodb server accessible via the given url

    Args:
        url (str): url of the mongodb server

    Returns:
        mongodb client

    """
    return MongoClient(url)


def build_new_mongo_databases_and_collection(client):
    """
    Fill:
        Create the top-level mongodb for TAXII, discovery_database, with its two collections:
        discovery_information and api_root_info

    Args:
        client (pymongo.MongoClient): mongodb client connection

    Returns:
        discovery_database object

    """
    db = client["discovery_database"]
    return db


def add_api_root(client, url=None, title=None, description=None, versions=None, max_content_length=0, default=False):
    """
    Fill:
        Create a mongodb for a new api root, with collections: status, objects, manifest, (TAXII) collections.
        Update top-level mongodb for TAXII, discovery_database, with information about this api root.

    Args:
        client (pymongo.MongoClient): mongodb client connection
        url (str): url of this api root
        title (str):  title of this api root
        description (str): description of this api root
        versions (list of str):  versions of TAXII serviced by this api root
        max_content_length (int):  maximum size of requests to this api root
        default (bool):  is this the default api root for this TAXII server

    Returns:
        new api_root_db object

    """
    if not versions:
        versions = ["application/taxii+json;version=2.1"]
    db = client["discovery_database"]
    url_parts = url.split("/")
    name = url_parts[-2]
    discovery_info = db["discovery_information"]
    info = discovery_info.find_one()
    info["api_roots"].append(name)
    discovery_info.update_one({"_id": info["_id"]}, {"$set": {"api_roots": info["api_roots"]}})
    api_root_info = db["api_root_info"]
    api_root_info.insert_one({
        "_url": url,
        "_name": name,
        "title": title,
        "description": description,
        "versions": versions,
        "max_content_length": max_content_length,
    })
    api_root_db = client[name]
    return api_root_db


def reset_db(url=MONGODB_URL):
    client = connect_to_client(url)
    client.drop_database("discovery_database")
    db = build_new_mongo_databases_and_collection(client)

    db["discovery_information"].insert_one({
        "title": "Some TAXII Server",
        "description": "This TAXII Server contains a listing of",
        "contact": "string containing contact information",
        "default": "https://taxii.obi1.dk/trustgroup1/",
        "api_roots": [],
    })

    client.drop_database("api1")
    add_api_root(
        client,
        url="https://taxii.obi1.dk/api1/",
        title="General STIX 2.1 Collections",
        description="A repo for general STIX data.",
        max_content_length=9765625,
    )

    client.drop_database("api2")
    add_api_root(
        client,
        url="https://taxii.obi1.dk/api2/",
        title="STIX 2.1 Indicator Collections",
        description="A repo for general STIX data.",
        max_content_length=9765625,
    )

    client.drop_database("trustgroup1")
    api_root_db = add_api_root(
        client,
        url="https://taxii.obi1.dk/trustgroup1/",
        title="Malware Research Group",
        description="A trust group setup for malware researchers",
        max_content_length=9765625,
        default=True,
    )
    api_root_db["status"].insert_many([
        {
            "id": "2d086da7-4bdc-4f91-900e-d77486753710",
            "status": "pending",
            "request_timestamp": "2016-11-02T12:34:34.123456Z",
            "total_count": 4,
            "success_count": 1,
            "successes": [
                {
                    "id": "indicator--a932fcc6-e032-176c-126f-cb970a5a1ade",
                    "version": "2014-05-08T09:00:00.000Z",
                    "message": "Successfully added object to collection '91a7b528-80eb-42ed-a74d-c6fbd5a26116'."
                }
            ],
            "failure_count": 1,
            "failures": [
                {
                    "id": "malware--664fa29d-bf65-4f28-a667-bdb76f29ec98",
                    "version": "2015-05-08T09:00:00.000Z",
                    "message": "Unable to process object",
                },
            ],
            "pending_count": 2,
            "pendings": [
                {
                    "id": "indicator--252c7c11-daf2-42bd-843b-be65edca9f61",
                    "version": "2016-08-08T09:00:00.000Z",
                },
                {
                    "id": "relationship--045585ad-a22f-4333-af33-bfd503a683b5",
                    "version": "2016-06-08T09:00:00.000Z",
                }
            ],
        },
        {
            "id": "2d086da7-4bdc-4f91-900e-f4566be4b780",
            "status": "pending",
            "request_timestamp": "2016-11-02T12:34:34.123456Z",
            "total_objects": 0,
            "success_count": 0,
            "successes": [],
            "failure_count": 0,
            "failures": [],
            "pending_count": 0,
            "pendings": [],
        },
    ])

    api_root_db["collections"].insert_one({
        "id": "472c94ae-3113-4e3e-a4dd-a9f4ac7471d4",
        "title": "This data collection is for testing querying across collections",
        "can_read": False,
        "can_write": True,
        "media_types": [
            "application/stix+json;version=2.1",
        ],
    })

    api_root_db["collections"].insert_one({
        "id": "365fed99-08fa-fdcd-a1b3-fb247eb41d01",
        "title": "This data collection is for testing querying across collections",
        "can_read": True,
        "can_write": True,
        "media_types": [
            "application/stix+json;version=2.1",
        ],
    })

    api_root_db["collections"].insert_one({
        "id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
        "title": "High Value Indicator Collection",
        "description": "This data collection is for collecting high value IOCs",
        "can_read": True,
        "can_write": True,
        "media_types": [
            "application/stix+json;version=2.0",
            "application/stix+json;version=2.1",
        ],
    })

    api_root_db["collections"].insert_one({
        "id": "52892447-4d7e-4f70-b94d-d7f22742ff63",
        "title": "Indicators from the past 24-hours",
        "description": "This data collection is for collecting current IOCs",
        "can_read": True,
        "can_write": False,
        "media_types": [
            "application/stix+json;version=2.1",
        ],
    })

    api_root_db["collections"].insert_one({
        "id": "64993447-4d7e-4f70-b94d-d7f33742ee63",
        "title": "Secret Indicators",
        "description": "Non accessible",
        "can_read": False,
        "can_write": False,
        "media_types": [
            "application/stix+json;version=2.1",
        ],
    })

    api_root_db["objects"].insert_many([
        {
            "created": datetime_to_float(string_to_datetime("2014-05-08T09:00:00.000Z")),
            "modified": datetime_to_float(string_to_datetime("2014-05-08T09:00:00.000Z")),
            "id": "relationship--2f9a9aa9-108a-4333-83e2-4fb25add0463",
            "relationship_type": "indicates",
            "source_ref": "indicator--cd981c25-8042-4166-8945-51178443bdac",
            "spec_version": "2.1",
            "target_ref": "malware--c0931cc6-c75e-47e5-9036-78fabc95d4ec",
            "type": "relationship",
            "_collection_id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
            "_manifest": {
                "date_added": datetime_to_float(string_to_datetime("2014-05-08T09:00:00.000000Z")),
                "id": "relationship--2f9a9aa9-108a-4333-83e2-4fb25add0463",
                "media_type": "application/stix+json;version=2.1",
                "version": datetime_to_float(string_to_datetime("2014-05-08T09:00:00.000Z")),
            },
        },
        {
            "created": datetime_to_float(string_to_datetime("2014-05-08T09:00:00.000Z")),
            "id": "indicator--cd981c25-8042-4166-8945-51178443bdac",
            "indicator_types": [
                "file-hash-watchlist",
            ],
            "modified": datetime_to_float(string_to_datetime("2014-05-08T09:00:00.000Z")),
            "name": "File hash for Poison Ivy variant",
            "pattern": "[file:hashes.'SHA-256' = 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c']",
            "pattern_type": "stix",
            "spec_version": "2.1",
            "type": "indicator",
            "valid_from": "2014-05-08T09:00:00.000000Z",
            "_collection_id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
            "_manifest": {
                "date_added": datetime_to_float(string_to_datetime("2016-11-01T03:04:05.000000Z")),
                "id": "indicator--cd981c25-8042-4166-8945-51178443bdac",
                "media_type": "application/stix+json;version=2.1",
                "version": datetime_to_float(string_to_datetime("2014-05-08T09:00:00.000Z")),
            },
        },
        {
            "created": datetime_to_float(string_to_datetime("2016-11-03T12:30:59.000Z")),
            "description": "Accessing this url will infect your machine with malware.",
            "id": "indicator--6770298f-0fd8-471a-ab8c-1c658a46574e",
            "indicator_types": [
                "url-watchlist",
            ],
            "modified": datetime_to_float(string_to_datetime("2016-11-03T12:30:59.000Z")),
            "name": "Malicious site hosting downloader",
            "pattern": "[url:value = 'http://z4z10farb.cn/4712']",
            "pattern_type": "stix",
            "spec_version": "2.1",
            "type": "indicator",
            "valid_from": "2017-01-27T13:49:53.935382Z",
            "_collection_id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
            "_manifest": {
                "date_added": datetime_to_float(string_to_datetime("2016-11-03T12:30:59.001000Z")),
                "id": "indicator--6770298f-0fd8-471a-ab8c-1c658a46574e",
                "media_type": "application/stix+json;version=2.1",
                "version": datetime_to_float(string_to_datetime("2016-11-03T12:30:59.000Z")),
            },
        },
        {
            "created": datetime_to_float(string_to_datetime("2016-11-03T12:30:59.000Z")),
            "description": "Accessing this url will infect your machine with malware. Updated indicator",
            "id": "indicator--6770298f-0fd8-471a-ab8c-1c658a46574e",
            "indicator_types": [
                "url-watchlist",
            ],
            "modified": datetime_to_float(string_to_datetime("2016-12-25T12:30:59.444Z")),
            "name": "Malicious site hosting downloader",
            "pattern": "[url:value = 'http://x4z9arb.cn/4712']",
            "pattern_type": "stix",
            "spec_version": "2.1",
            "type": "indicator",
            "valid_from": "2017-01-27T13:49:53.935382Z",
            "_collection_id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
            "_manifest": {
                "date_added": datetime_to_float(string_to_datetime("2016-12-27T13:49:59.000000Z")),
                "id": "indicator--6770298f-0fd8-471a-ab8c-1c658a46574e",
                "media_type": "application/stix+json;version=2.1",
                "version": datetime_to_float(string_to_datetime("2016-12-25T12:30:59.444Z")),
            },
        },
        {
            "created": datetime_to_float(string_to_datetime("2016-11-03T12:30:59.000Z")),
            "description": "Accessing this url will infect your machine with malware. This is the last updated indicator",
            "id": "indicator--6770298f-0fd8-471a-ab8c-1c658a46574e",
            "indicator_types": [
                "url-watchlist",
            ],
            "modified": datetime_to_float(string_to_datetime("2017-01-27T13:49:53.935Z")),
            "name": "Malicious site hosting downloader",
            "pattern": "[url:value = 'http://x4z9arb.cn/4712']",
            "pattern_type": "stix",
            "spec_version": "2.1",
            "type": "indicator",
            "valid_from": "2016-11-03T12:30:59.000Z",
            "_collection_id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
            "_manifest": {
                "date_added": datetime_to_float(string_to_datetime("2017-12-31T13:49:53.935000Z")),
                "id": "indicator--6770298f-0fd8-471a-ab8c-1c658a46574e",
                "media_type": "application/stix+json;version=2.1",
                "version": datetime_to_float(string_to_datetime("2017-01-27T13:49:53.935Z")),
            },
        },
        {
            "created": datetime_to_float(string_to_datetime("2017-01-20T00:00:00.000Z")),
            "definition": {
                "tlp": "green",
            },
            "definition_type": "tlp",
            "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            "name": "TLP:GREEN",
            "spec_version": "2.1",
            "type": "marking-definition",
            "_collection_id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
            "_manifest": {
                "date_added": datetime_to_float(string_to_datetime("2017-01-20T00:00:00.000000Z")),
                "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
                "media_type": "application/stix+json;version=2.1",
                "version": datetime_to_float(string_to_datetime("2017-01-20T00:00:00.000Z")),
            },
        },
        {
            "created": datetime_to_float(string_to_datetime("2017-01-27T13:49:53.997Z")),
            "description": "Poison Ivy",
            "id": "malware--c0931cc6-c75e-47e5-9036-78fabc95d4ec",
            "is_family": True,
            "malware_types": [
                "remote-access-trojan",
            ],
            "modified": datetime_to_float(string_to_datetime("2017-01-27T13:49:53.997Z")),
            "name": "Poison Ivy",
            "spec_version": "2.1",
            "type": "malware",
            "_collection_id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
            "_manifest": {
                "date_added": datetime_to_float(string_to_datetime("2017-01-27T13:49:59.997000Z")),
                "id": "malware--c0931cc6-c75e-47e5-9036-78fabc95d4ec",
                "media_type": "application/stix+json;version=2.1",
                "version": datetime_to_float(string_to_datetime("2017-01-27T13:49:53.997Z")),
            },
        },
        {
            "created": datetime_to_float(string_to_datetime("2017-01-27T13:49:53.997Z")),
            "description": "Poison Ivy",
            "id": "malware--c0931cc6-c75e-47e5-9036-78fabc95d4ec",
            "is_family": True,
            "malware_types": [
                "remote-access-trojan"
            ],
            "modified": datetime_to_float(string_to_datetime("2018-02-23T18:30:00.000Z")),
            "name": "Poison Ivy",
            "type": "malware",
            "_collection_id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
            "_manifest": {
                "date_added": datetime_to_float(string_to_datetime("2017-01-27T13:49:59.997000Z")),
                "id": "malware--c0931cc6-c75e-47e5-9036-78fabc95d4ec",
                "media_type": "application/stix+json;version=2.0",
                "version": datetime_to_float(string_to_datetime("2018-02-23T18:30:00.000Z")),
            },
        },
    ])

    id_index = IndexModel([("id", ASCENDING)])
    type_index = IndexModel([("type", ASCENDING)])
    collection_index = IndexModel([("_collection_id", ASCENDING)])
    date_index = IndexModel([("_manifest.date_added", ASCENDING)])
    version_index = IndexModel([("_manifest.version", ASCENDING)])
    date_and_spec_index = IndexModel([("_manifest.media_type", ASCENDING), ("_manifest.date_added", ASCENDING)])
    version_and_spec_index = IndexModel([("_manifest.media_type", ASCENDING), ("_manifest.version", ASCENDING)])
    collection_and_date_index = IndexModel([("_collection_id", ASCENDING), ("_manifest.date_added", ASCENDING)])
    api_root_db["objects"].create_indexes(
        [id_index, type_index, date_index, version_index, collection_index, date_and_spec_index,
         version_and_spec_index, collection_and_date_index]
    )


def wipe_mongodb_server():
    """remove all databases on the server (excluding required MongoDB system databases)"""
    client = connect_to_client()

    for db in set(client.list_database_names()) - set(["admin", "config", "local"]):
        client.drop_database(db)


if __name__ == "__main__":
    reset_db()