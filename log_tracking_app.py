#!/usr/bin/env python3

from collections import namedtuple
from datetime import datetime, timezone as tz
import json

import requests


RECORD_NT = namedtuple("record", "type content timestamp")
logdate = lambda m, d, dt: datetime.strptime(f"{m} {d} {dt}", "%b %d %X")


class BaseRecord:
    _FIELDS = [
        "content",
        "timestamp",
        "logdate",
        "user",
        "ipaddr",
        "ipinfo",
        "port",
        "data",
    ]

    def __init__(self, record):
        self.data = None
        self.logdate = None
        self.ipaddr = None
        self.ipinfo = None
        self.port = None
        self.user = None
        self.content = record.content
        self.timestamp = self._fromiso(record.timestamp)

    @classmethod
    def from_record(cls, record):
        obj = cls(record)
        if hasattr(obj, "parse"):
            obj.parse()
        obj.ipinfo = obj.fetch_ip_info(obj.ipaddr)
        return obj

    @staticmethod
    def _fromiso(timestamp):
        return datetime.fromisoformat(
            timestamp[:-1]
        )  # .replace(tzinfo=tz.utc)

    @staticmethod
    def fetch_ip_info(ipaddr):
        if ipaddr is None:
            return
        resp = requests.get(f"https://ipinfo.io/{ipaddr}")
        if resp.status_code != 200:
            return
        data = resp.json()
        coords = [float(c) for c in data["loc"].split(",")]
        return {
            "country": data["country"],
            "city": data["city"],
            "lat": coords[0],
            "lon": coords[1],
            "region": data["region"],
            "timezone": data["timezone"],
            "org": data.get("org"),
        }

    def as_dict(self):
        dct = {k: getattr(self, k) for k in self._FIELDS if hasattr(self, k)}
        return {"type": self.__class__.__name__, **dct}


class SSH_INVALID(BaseRecord):
    def __init__(self, record):
        super().__init__(record)

    def parse(self):
        mo, day, daytime, host, *fields = self.content.split(" ")
        self.user, self.ipaddr, self.port = fields[3::2]
        self.logdate = logdate(mo, day, daytime)


class UFW_BLOCK(BaseRecord):
    def __init__(self, record):
        super().__init__(record)

    def parse(self):
        meta, data = self.content.split(" [UFW BLOCK] ")
        mo, day, daytime, host, *_ = meta.split(" ")
        self.logdate = logdate(mo, day, daytime)
        self.data = {}
        for field in data.split(" "):
            try:
                k, v = field.split("=")
            except ValueError:
                k, v = field, None
            self.data[k] = v
        self.ipaddr = self.data["SRC"]


def main(logrecord: dict, prev_data=None):
    raw_record = RECORD_NT(**logrecord)
    obj = globals()[raw_record.type].from_record(raw_record)
    with open("_MSIO/EXEC_IN.json") as f:
        print(f.read())
    return obj.as_dict()


if __name__ == "__main__":  # Local testing

    def stream_data():
        with open("samples.jsonl") as f:
            for line in f.readlines():
                if line := line.strip():
                    yield RECORD_NT(**json.loads(line))

    for en, rec in enumerate(stream_data()):
        parsed_rec = globals()[rec.type].from_record(rec)
        print(parsed_rec.as_dict())
        if en == 3:
            break
