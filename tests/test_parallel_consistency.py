"""Cross-process proof of stateless pseudonym consistency: N worker processes
independently compute pseudonyms for the same entities with zero coordination
and must agree bit-for-bit."""
import multiprocessing as mp

ENTITIES = [
    ("PERSON", "priya sharma"), ("PERSON", "anil rao"), ("ORG", "apex solutions"),
    ("LOCATION", "new delhi"), ("EMAIL", "a@b.com"), ("PERSON", "meera iyer"),
]


def _worker_tokens(_):
    # imported fresh in each process: no shared state whatsoever
    from anonymizer.core.pseudonym import PseudonymEngine

    engine = PseudonymEngine(b"\x5a" * 32, length=8)
    return [engine.token(t, c) for t, c in ENTITIES]


def test_parallel_workers_agree_bitwise():
    try:
        ctx = mp.get_context("fork")
    except ValueError:
        ctx = mp.get_context("spawn")
    with ctx.Pool(4) as pool:
        results = pool.map(_worker_tokens, range(4))
    assert all(r == results[0] for r in results), "workers disagreed on pseudonyms"


def test_sequential_runs_agree_within_salt_scope():
    from anonymizer.core.pseudonym import PseudonymEngine

    run1 = PseudonymEngine(b"\x5a" * 32).token("PERSON", "priya sharma")
    run2 = PseudonymEngine(b"\x5a" * 32).token("PERSON", "priya sharma")
    assert run1 == run2
