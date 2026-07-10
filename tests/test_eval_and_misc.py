"""Evaluation harness KPIs, redline, dates, policy YAML loading, salt scoping."""
import os
import tempfile

from anonymizer.core import dates
from anonymizer.core.redline import redline_html
from anonymizer.core.policyload import load_policy_yaml
from anonymizer.core.types import JobSpec, Target
from anonymizer.evalharness import run_eval


def test_eval_kpis():
    report = run_eval(n_docs=25, seed=7)
    for mode in ("training", "rag"):
        assert report[mode]["residual_leak_rate"] == 0.0, report
        assert report[mode]["quarantined_docs"] == 0, report
    assert report["rag"]["consistency_rate"] == 1.0, report
    assert report["rag"]["false_merges"] == 0, report
    assert report["rag"]["entities_tracked"] > 10


def test_date_shift_preserves_intervals_and_format():
    s1 = dates.shift_date("2024-03-12", 40)
    s2 = dates.shift_date("2024-03-15", 40)
    assert s1 == "2024-04-21" and s2 == "2024-04-24"  # 3-day gap preserved
    assert dates.shift_date("12/03/2024", 1) == "13/03/2024"  # format preserved
    assert dates.shift_date("March 12, 2024", 1) == "March 13, 2024"
    assert dates.shift_date("not a date", 5) is None


def test_year_only():
    assert dates.year_only("12 March 2024") == "2024"


def test_redline_html_marks_changes():
    html = redline_html("Priya Sharma called", "<NAME_1> called",
                        file_id="f1", mode="training", policy_version="1",
                        status="VERIFIED", count=1)
    assert "<del>" in html and "<ins>" in html
    assert "&lt;NAME_1&gt;" in html  # escaped
    assert "Priya" in html  # dry-run preview intentionally shows original


def test_policy_yaml_loading(tmp_path=None):
    yaml_text = """
version: "9"
policies:
  training:
    PERSON: {strategy: placeholder_indexed, token: NAME}
    DATE: date_shift
  rag:
    PERSON: hmac_pseudonym
"""
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as fh:
        fh.write(yaml_text)
    try:
        table = load_policy_yaml(path)
        assert table.version == "9"
        assert table.lookup("training", "person").strategy.value == "placeholder_indexed"
        # fail closed for unknown types
        assert table.lookup("training", "MYSTERY").strategy.value == "suppress"
    finally:
        os.unlink(path)


def test_salt_scope_derivation():
    from anonymizer.secrets import EnvProvider

    os.environ["ANON_T1_HMAC_SALT"] = "ab" * 32
    p = EnvProvider()
    tenant = p.hmac_salt(JobSpec(job_id="j1", target=Target.RAG, tenant_id="t1"))
    corpus = p.hmac_salt(JobSpec(job_id="j1", target=Target.RAG, tenant_id="t1",
                                 salt_scope="corpus", corpus_id="c1"))
    run1 = p.hmac_salt(JobSpec(job_id="j1", target=Target.RAG, tenant_id="t1",
                               salt_scope="run"))
    run2 = p.hmac_salt(JobSpec(job_id="j2", target=Target.RAG, tenant_id="t1",
                               salt_scope="run"))
    assert len({bytes(tenant), bytes(corpus), bytes(run1), bytes(run2)}) == 4
    # run scope: same job -> same salt; different job -> different (documented)
    assert p.hmac_salt(JobSpec(job_id="j1", target=Target.RAG, tenant_id="t1",
                               salt_scope="run")) == run1
