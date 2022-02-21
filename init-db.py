from pymongo import ASCENDING, IndexModel, MongoClient


def reset_db(url="mongodb://taxiidb:MwSZboPcpKkQfN07@cluster0-shard-00-00.r7tjd.mongodb.net:27017,cluster0-shard-00-01.r7tjd.mongodb.net:27017,cluster0-shard-00-02.r7tjd.mongodb.net:27017/myFirstDatabase?ssl=true&replicaSet=atlas-7vk6bi-shard-0&authSource=admin&retryWrites=true&w=majority"):
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

    client.drop_database("trustgroup1")
    api_root_db = add_api_root(
        client,
        url="https://taxii.obi1.dk/trustgroup1/",
        title="Malware Research Group",
        description="A trust group setup for malware researchers",
        max_content_length=9765625,
        default=True,
    )

    api_root_db["collections"].insert_one({
        "id": "64993447-4d7e-4f70-b94d-d7f33742ee63",
        "title": "Secret Indicators",
        "description": "Non accessible",
        "can_read": True,
        "can_write": True,
        "media_types": [
            "application/stix+json;version=2.1",
        ],
    })

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


def connect_to_client(url="mongodb://taxiidb:MwSZboPcpKkQfN07@cluster0-shard-00-00.r7tjd.mongodb.net:27017,cluster0-shard-00-01.r7tjd.mongodb.net:27017,cluster0-shard-00-02.r7tjd.mongodb.net:27017/myFirstDatabase?ssl=true&replicaSet=atlas-7vk6bi-shard-0&authSource=admin&retryWrites=true&w=majority"):
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


if __name__ == "__main__":
    reset_db()
