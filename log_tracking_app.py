#!/usr/bin/env python3

from collections import defaultdict, namedtuple
from datetime import datetime as dt
import json

import numpy as np
import requests
from scipy import stats as scipy_stats


RECORD_NT = namedtuple("record", "type content timestamp")
logdate = (
    lambda m, d, tm: f"{dt.strptime(f'{m} {d} {tm}', '%b %d %X'):%b-%d %H:%M:%S}"
)


class BaseRecord:
    def __init__(self, record):
        self.type = self.__class__.__name__
        self.content = record.content
        self.timestamp = self._fromiso(record.timestamp)
        self.data = None
        self.ipaddr = None
        self.ipinfo = None

    @classmethod
    def from_record(cls, record):
        obj = cls(record)
        if hasattr(obj, "parse"):
            obj.parse()
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
        return {
            k: getattr(self, k)
            for k in [
                "type",
                "timestamp",
                "ipaddr",
                "ipinfo",
                "data",
            ]
        }


class SSH_INVALID(BaseRecord):
    def __init__(self, record):
        super().__init__(record)

    def parse(self):
        mo, day, daytime, host, *fields = self.content.split(" ")
        user, self.ipaddr, port = fields[3::2]
        self.data = {
            "logdate": logdate(mo, day, daytime),
            "user": user,
            "port": port,
        }


class UFW_BLOCK(BaseRecord):
    def __init__(self, record):
        super().__init__(record)

    def parse(self):
        meta, data = self.content.split(" [UFW BLOCK] ")
        mo, day, daytime, host, *_ = meta.split(" ")
        ddct = {}
        for field in data.split(" "):
            try:
                k, v = field.split("=")
            except ValueError:
                k, v = field, None
            ddct[k] = v
        self.ipaddr = ddct["SRC"]
        self.data = {"logdate": logdate(mo, day, daytime), **ddct}


def make_stats(data, trailing_hrs: int = 1):
    def calc_rate(tss):
        idxs = tss > np.datetime64(dt.utcnow()) - np.timedelta64(
            trailing_hrs, "h"
        )
        rate_per_minute = None
        if len(dts := np.diff(tss[idxs]) / np.timedelta64(1, "m")) > 1:
            rate_per_minute = np.around(1 / scipy_stats.expon.fit(dts)[1], 2)
        return {"rate_per_minute": rate_per_minute, "count": int(np.sum(idxs))}

    event_types = np.array(data["type"])
    tss = np.array(data["timestamp"]).astype(np.datetime64)
    stats = {"__ALL__": calc_rate(tss), "trailing_hrs": trailing_hrs}
    for etype in np.unique(event_types):
        stats[etype] = calc_rate(tss[event_types == etype])
    return stats


def main(logrecord: dict, prev_data=None, trailing_hrs: int = 1):
    raw_record = RECORD_NT(**logrecord)
    obj = globals()[raw_record.type].from_record(raw_record)
    prev_data = prev_data or defaultdict(list)
    ipaddr_idx = prev_data.get("ipaddr", []).index(obj.ipaddr)
    print(ipaddr_idx)
    obj.ipinfo = obj.fetch_ip_info(obj.ipaddr)

    for k in prev_data or {}:
        if hasattr(obj, k):
            prev_data[k].append(getattr(obj, k))
    stats = make_stats(data=prev_data, trailing_hrs=trailing_hrs)
    with open("page.html") as f:
        html = f.read()
    return {**obj.as_dict(), "stats": stats, "html": html}


if __name__ == "__main__":  # Local testing

    def stream_data():
        with open("samples.jsonl") as f:
            for line in f.readlines():
                if line := line.strip():
                    yield json.loads(line)

    prev_data = {"timestamp": [], "type": [], "stats": []}
    trailing_hrs = 1000

    for en, rec in enumerate(stream_data()):
        entry = main(rec, prev_data, trailing_hrs)
        prev_data["stats"].append(entry["stats"])
        if en == 400:
            break
    prn(prev_data["stats"])
