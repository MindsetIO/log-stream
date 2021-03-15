#!/usr/bin/env python3

from collections import deque
from datetime import datetime
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
    _ts = f"{datetime.today().year} {mo} {int(day):2d} {hhmm}"
    timestamp = datetime.strptime(_ts, "%Y %b %d %X")
    return timestamp


def record_parse(content, split_with):
    meta, rec = content.split(split_with)
    mo, day, hhmm, host, *_ = [s for s in meta.split(" ") if s]
    timestamp = format_timestamp(mo, day, hhmm)
    common = {"host": host, "timestamp": f"{timestamp}"}
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
def parse_ufw_block(content):
    common_dct, rec = record_parse(content, " [UFW BLOCK] ")
    parsed_dct = {
        ss[0]: ss[1] or None for s in rec if len(ss := s.split("=")) == 2
    }
    return common_dct, parsed_dct


@log_decorator("SRC")
def parse_ssh_invalid(content):
    for split_by, record_type, idxs in [
        (": Invalid user ", "SSH_INVALID", [4, 2, 0]),
        (": Connection closed by authenticating user ", "SSH_AUTH", [3, 1, 0]),
    ]:
        try:
            common_dct, rec = record_parse(content, split_by)
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


def make_page(history, tablelen):
    params = {
        "data": history,
        "tablelen": tablelen,
        "world": WORLD_JSON,
        "username": os.environ.get("MSIO_USERNAME"),
        "app_idn": os.environ.get("MSIO_APP_ALIAS")
        or os.environ.get("MSIO_APP_ID"),
    }
    html = TEMPLATE.render(**params)
    return html


def main(record, history=None, tablelen=10):
    print(f"{history=}")
    if bool(rec := record):
        func_name = f"parse_{record['type'].lower()}"
        rec = globals()[func_name](record["content"])
    data = (history or {}).get("record", []) + [rec] if rec else []
    html = make_page(data, tablelen)
    return {"record": rec, "html": html}


if __name__ == "__main__":  # Local testing

    def stream_data():
        with open("sample.jsonl") as f:
            for line in f.readlines():
                if line := line.strip():
                    yield json.loads(line)

    os.environ["MSIO_USERNAME"] = "local-user"
    os.environ["MSIO_APP_ALIAS"] = "log-tracker"
    history, tablelen = {'record': []}, 15
    for record in stream_data():
        resp = main(record, history, tablelen=tablelen)
        history['record'].append(resp["record"])

    with open(f"/tmp/page.html", "w") as f:
        f.write(resp["html"])
