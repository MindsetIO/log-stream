#!/usr/bin/env python3

from collections import defaultdict
from datetime import datetime as dt
from functools import wraps
import json
import os

import geoip2.database
from jinja2 import Environment, FileSystemLoader


GEO_DB_PATH = "/data/GeoIP2/GeoLite2-City.mmdb"
TEMPLATE_DIR = os.path.dirname(os.path.realpath(__file__))
TEMPLATE_ENV = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
TEMPLATE = TEMPLATE_ENV.get_template("template.html")
with open("world.json") as fh:
    WORLD_JSON = fh.read()


def format_timestamp(mo, day, hhmm):
    _ts = f"{dt.today().year} {mo} {int(day):2d} {hhmm}"
    timestamp = dt.strptime(_ts, "%Y %b %d %X")
    return timestamp


def record_parse(logline, split_with):
    meta, rec = logline["content"].split(split_with)
    mo, day, hhmm, host, *_ = [s for s in meta.split(" ") if s]
    event_time = format_timestamp(mo, day, hhmm)
    common = {
        "host": host,
        "event_time": f"{event_time}",
        "timestamp": logline["timestamp"],
    }
    return common, rec.split(" ")


def log_decorator(ip_key):
    def deco(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            cdct, pdct = func(*args, **kwargs)
            rec_type = func.__name__.removeprefix("parse_").upper()
            geoip = geo_data(pdct[ip_key])
            dct = {**cdct, **pdct, "type": rec_type, "geoip": geoip}
            return dct

        return wrapper

    return deco


@log_decorator("SRC")
def parse_ufw_block(logline):
    common_dct, rec = record_parse(logline, " [UFW BLOCK] ")
    parsed_dct = {
        ss[0]: ss[1] or None for s in rec if len(ss := s.split("=")) == 2
    }
    return common_dct, parsed_dct


@log_decorator("SRC")
def parse_ssh_invalid(logline):
    for split_by, record_type, idxs in [
        (": Invalid user ", "SSH_INVALID", [4, 2, 0]),
        (": Connection closed by authenticating user ", "SSH_AUTH", [3, 1, 0]),
    ]:
        try:
            common_dct, rec = record_parse(logline, split_by)
            parsed_dct = {
                "DPT": rec[idxs[0]],
                "SRC": rec[idxs[1]],
                "USERNAME": rec[idxs[2]],
            }
            return common_dct, parsed_dct
        except ValueError:
            pass


def geo_data(ipaddr):
    with geoip2.database.Reader(GEO_DB_PATH) as reader:
        city = reader.city(ipaddr)
    dct = {
        "iso_code": city.country.iso_code,
        "country": city.country.name,
        "subdivision": city.subdivisions.most_specific.iso_code,
        "city": city.city.name,
        "coords": {
            "lat": city.location.latitude,
            "lon": city.location.longitude,
        },
    }
    return dct


def make_stats(history):

    adct, sdct = {}, defaultdict(list)
    for rec in history:
        print(rec)
        if rec is None:
            continue
        sdct[rec["type"]].append(dt.fromisoformat(rec["timestamp"][:-1]))
    for k, v in sdct.items():
        tdiff = [(t1 - t0).total_seconds() for t0, t1 in zip(v[:-1], v[1:])]
        try:
            adct[k] = {
                "rate_min": 60 / sum(tdiff) * len(tdiff),
                "count": len(v),
            }
        except ZeroDivisionError:
            pass
    return adct


def make_page(history, tablelen, stats):
    params = {
        "data": history,
        "tablelen": tablelen,
        "world": WORLD_JSON,
        "stats": stats,
        "username": os.environ.get("MSIO_USERNAME"),
        "app_idn": os.environ.get("MSIO_APP_ALIAS")
        or os.environ.get("MSIO_APP_ID"),
    }
    html = TEMPLATE.render(**params)
    return html


def main(logline, record=None, tablelen=10):
    new_record = None
    if logline:
        func_name = f"parse_{logline['type'].lower()}"
        new_record = globals()[func_name](logline)
    history = (record or []) + [new_record] if new_record else []
    stats = make_stats(history)
    html = make_page(history, tablelen, stats)
    return {"record": new_record, "html": html, "stats": stats}


if __name__ == "__main__":  # Local testing

    def stream_data():
        with open("sample.jsonl") as f:
            for line in f.readlines():
                if line := line.strip():
                    yield json.loads(line)

    os.environ["MSIO_USERNAME"] = "msio-team"
    os.environ["MSIO_APP_ALIAS"] = "logtrack"
    tablelen = 10

    # Locally simlulate stream
    record = []
    for logline in stream_data():
        resp = main(logline, record, tablelen=tablelen)
        record.append(resp["record"])

    with open(f"/tmp/page.html", "w") as f:
        f.write(resp["html"])
