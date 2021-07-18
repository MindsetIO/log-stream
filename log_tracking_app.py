#!/usr/bin/env python3

from collections import namedtuple
from datetime import datetime as dt
import json

import numpy as np
import requests
from scipy import stats as scipy_stats


RECORD_NT = namedtuple("record", "type content timestamp")
logdate = lambda m, d, ts: dt.strptime(f"{m} {d} {ts}", "%b %d %X")


class BaseRecord:
    _FIELDS = [
        "type",
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
        self.type = self.__class__.__name__
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
        # obj.ipinfo = obj.fetch_ip_info(obj.ipaddr)
        return obj

    @staticmethod
    def _fromiso(timestamp):
        return dt.fromisoformat(timestamp[:-1])

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
        return {k: getattr(self, k) for k in self._FIELDS if hasattr(self, k)}


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


def make_stats(data, trailing_hrs: int = 1):
    tss = np.array(data["timestamp"]).astype(np.datetime64)
    idxs = tss > np.datetime64(dt.utcnow()) - np.timedelta64(trailing_hrs, "h")
    rate_per_minute = None
    if len(dts := np.diff(tss[idxs]) / np.timedelta64(1, "m")) > 1:
        rate_per_minute = 1 / scipy_stats.expon.fit(dts)[1]
    return {"rate_per_minute": rate_per_minute}


def main(logrecord: dict, prev_data=None, trailing_hours: int = 1):
    raw_record = RECORD_NT(**logrecord)
    obj = globals()[raw_record.type].from_record(raw_record)
    for k in prev_data or {}:
        if hasattr(obj, k):
            prev_data[k].append(getattr(obj, k))
    stats = make_stats(data=prev_data, trailing_hrs=trailing_hours)
    rv = {**obj.as_dict(), "stats": stats}
    print(rv)
    return rv


if __name__ == "__main__":  # Local testing

    def stream_data():
        with open("samples.jsonl") as f:
            for line in f.readlines():
                if line := line.strip():
                    yield json.loads(line)

    prev_data = {"ipinfo": [], "timestamp": [], "type": []}
    for en, rec in enumerate(stream_data()):
        entry = main(rec, prev_data, 1000)
        if en == 300:
            break
