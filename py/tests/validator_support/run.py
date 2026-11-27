"""Locating a case and running its submissions, as the conformance runner's evaluate verb."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path

from hop_top_pact import conformance
from hop_top_pact.core.clock import FakeClock
from hop_top_pact.validator import Request, Result, Validator
from validator_support.gateway import Gateway, GatewayState
from validator_support.keys import PrivateKey, load_private_keys


@dataclass
class Fixture:
    """The first submission of the first exchange of an evaluation case, ready to evaluate:
    the validator replica the case's gateway runs, over its stores, and the evaluate
    request. A test replaces a store or changes the request to see what the validator makes
    of it. clock is the validator's clock, held at the submission's start."""

    validator: Validator
    request: Request
    clock: FakeClock


def locate(directory: str | Path) -> tuple[Path, str]:
    """The fixture directory that holds directory, the nearest directory at or above it with a
    manifest.json, and the id of the evaluate entry whose path is directory."""
    abs_ = Path(directory).resolve()
    fixtures = abs_
    while not (fixtures / "manifest.json").exists():
        if fixtures.parent == fixtures:
            raise ValueError(f"{directory}: no manifest.json in it or above it")
        fixtures = fixtures.parent
    rel = abs_.relative_to(fixtures).as_posix()
    m = json.loads((fixtures / "manifest.json").read_bytes())
    for e in m["entries"]:
        if e["kind"] == "evaluate" and e["path"] == rel:
            return fixtures, str(e["id"])
    raise ValueError(f"{directory}: not the path of an evaluate entry")


def prepare(directory: str | Path) -> Fixture:
    """The Fixture of the evaluation case in directory. The case's publisher has registered
    the contract's nonce in the replay store."""
    fixtures, id_ = locate(directory)
    c = conformance.read(fixtures, id_)
    keys = load_private_keys(fixtures)
    x = c.exchanges[0]
    if not x.submissions:
        raise ValueError(f"{id_}: no submission")
    g = Gateway(fixtures, x, keys, GatewayState())
    sub = x.submissions[0]
    g.prepare_submission(sub)
    v, req = g.validator_for(sub, threading.Event())
    return Fixture(validator=v, request=req, clock=g.clk)


def run_exchanges(directory: str | Path) -> list[list[str]]:
    """Run the evaluation case in directory and return the responses of each exchange, in
    order: its submissions, then its handoff attempts. The replay store, the receipts and
    the consumed attestations carry over from one exchange to the next."""
    fixtures, id_ = locate(directory)
    c = conformance.read(fixtures, id_)
    keys = load_private_keys(fixtures)
    gs = GatewayState()
    return [_run_exchange(fixtures, x, keys, gs) for x in c.exchanges]


def run_case(directory: str | Path) -> list[str]:
    """Run the evaluation case in directory and return its responses, one per line: each
    exchange's submissions in order, then its handoff attempts."""
    return [ln for lines in run_exchanges(directory) for ln in lines]


def _run_exchange(
    fixtures: Path, x: conformance.Exchange, keys: dict[str, PrivateKey], gs: GatewayState
) -> list[str]:
    g = Gateway(fixtures, x, keys, gs)
    results: dict[str, Result] = {}
    lines = [""] * len(x.submissions)
    i = 0
    while i < len(x.submissions):
        batch = [i]
        while (
            x.submissions[i].concurrent
            and i + len(batch) < len(x.submissions)
            and x.submissions[i + len(batch)].concurrent
        ):
            batch.append(i + len(batch))
        lock = threading.Lock()
        threads: list[threading.Thread] = []
        for k in batch:
            sub = x.submissions[k]
            g.prepare_submission(sub)

            def work(
                k: int = k, sub: conformance.Submission = sub, lock: threading.Lock = lock
            ) -> None:
                res, ln, err = g.submit(sub)
                with lock:
                    if err is None and res is not None and res.receipt:
                        results[sub.jti] = res
                    lines[k] = ln

            t = threading.Thread(target=work)
            threads.append(t)
            t.start()
            if len(batch) == 1:
                t.join()
        for t in threads:
            t.join()
        i += len(batch)
    for h in x.handoff:
        lines.append(g.handoff(h, results.get(h.presentation)))
    return lines
