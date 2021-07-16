#!/usr/bin/env python3

from datetime import datetime as dt
import json
import logging
import re
import threading
import time
from os import environ
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(level=environ.get("LOGLEVEL", "INFO"))

BASE_URL = "https://api.mindset.io/apps"


class LogStream:
    REQ_ARGS = {
        "method": "POST",
        "headers": {
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "Syslog stream",
        },
    }

    def __init__(self, rec_type, logfile, regex, app_idn, api_key):
        self.api_key = environ.get("LOGGING_API_KEY") or api_key
        self.app_idn = environ.get("LOGGING_APP_IDN") or app_idn
        self.api_url = f"{BASE_URL}/{self.app_idn}/run?api_key={self.api_key}"
        self.rec_type = rec_type
        self.logfile = Path(logfile)
        self.regex = [regex] if isinstance(regex, str) else regex
        log.info(f"listening on {self.logfile}")

    @staticmethod
    def tail(fh):
        fh.seek(0, 2)
        while True:
            line = fh.readline()
            if line:
                yield line
            else:
                time.sleep(0.1)

    def post_record(self, record):
        logline = {
            "type": self.rec_type,
            "content": record,
            "timestamp": f"{dt.utcnow().isoformat()}Z",
        }
        data = json.dumps({"args": {"logline": logline}})
        with open("samples.jsonl", "a") as f:
            json.dump(logline, f)
            f.write("\n")
        log.info(f"posting log record ({self.rec_type}): {record}")
        req = Request(self.api_url, **self.REQ_ARGS, data=data.encode("utf8"))
        try:
            _ = urlopen(req)
        except HTTPError as e:
            log.error(f"HTTP ERROR: {e.msg} ({e.code})")
            log.error(f"{e.read().decode()}")

    def _matches(self, re_str):
        while True:
            record = (yield).strip()
            if re.findall(re_str, record):
                self.post_record(record)

    def stream(self):
        matches = [self._matches(smatch) for smatch in self.regex]
        _ = [next(m) for m in matches]
        while True:
            fh = open(self.logfile)
            for line in self.tail(fh):
                for m in matches:
                    m.send(line)


if __name__ == "__main__":
    with open(Path("config.json")) as f:
        config = json.load(f)
    settings = config.pop("settings", {"api_key": None, "app_idn": None})
    jobs = [
        threading.Thread(
            target=LogStream(stype, **params, **settings).stream, args=()
        )
        for stype, params in config.items()
    ]
    _ = [j.start() for j in jobs]
