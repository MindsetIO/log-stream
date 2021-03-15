#!/usr/bin/env python3

from datetime import datetime as dt
import json
import logging
import multiprocessing as mp
import re
import time
from os import environ
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(level=environ.get("LOGLEVEL", "INFO"))


class LogStream:
    API_URL = f"api.mindset.io/apps/logtrack/run?api_key={environ['API_KEY']}"
    HEADERS = {
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "Syslog stream",
    }

    def __init__(self, rec_type, logfile, regex):
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
        timestamp = f"{dt.utcnow().isoformat()}Z"
        data = json.dumps(
            {
                "data": {
                    "logline": {
                        "type": self.rec_type,
                        "content": record,
                        "timestamp": timestamp,
                    }
                }
            }
        )
        log.info(f"posting log record ({self.rec_type}): {record}")
        req = Request(
            f"https://{self.API_URL}",
            data=data.encode("utf8"),
            method="POST",
            headers=self.HEADERS,
        )
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
    jobs = [
        mp.Process(target=LogStream(stype, **params).stream, args=())
        for stype, params in config.items()
    ]
    _ = [j.start() for j in jobs]
