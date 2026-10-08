"""Motor-shaped adapter over mongomock; live Mongo remains the runtime gate."""
import asyncio
import mongomock


class Cursor:
    def __init__(self, cursor):
        self.cursor = cursor

    def limit(self, n):
        self.cursor = self.cursor.limit(n)
        return self

    async def to_list(self, length=None):
        return list(self.cursor)[:length]


class Collection:
    def __init__(self, collection):
        self.collection = collection
        self.failure = None

    def find(self, *args, **kwargs):
        return Cursor(self.collection.find(*args, **kwargs))

    def __getattr__(self, name):
        async def call(*args, **kwargs):
            await asyncio.sleep(0)
            if self.failure and name in ("update_one", "insert_one", "find_one_and_update"):
                raise self.failure
            return getattr(self.collection, name)(*args, **kwargs)
        return call


class Database:
    def __init__(self):
        self.raw = mongomock.MongoClient().db
        self.collections = {}

    def __getattr__(self, name):
        if name not in self.collections:
            self.collections[name] = Collection(self.raw[name])
        return self.collections[name]

    def __getitem__(self, name):
        return getattr(self, name)
