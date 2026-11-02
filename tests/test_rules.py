"""The rule table itself.

A rule that is unreachable, mislabelled or duplicated is a bug that no scan
will ever show, because nothing fires it. These tests read the table the way a
user does.
"""

from __future__ import annotations

from tlslint.model import SEVERITIES
from tlslint.rules import BY_ID, CATEGORIES, RULES, get, rules_for


def test_ids_are_unique():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))


def test_ids_are_sorted_and_contiguous_enough():
    ids = [r.id for r in RULES]
    assert ids == sorted(ids)


def test_every_rule_has_a_real_severity():
    for rule in RULES:
        assert rule.severity in SEVERITIES, rule.id


def test_every_rule_has_a_category_that_is_documented():
    for rule in RULES:
        assert rule.category in CATEGORIES, rule.id


def test_every_rule_names_a_standard():
    for rule in RULES:
        assert rule.standard.strip(), rule.id
        assert len(rule.standard) > 4, rule.id


def test_every_rule_explains_itself_and_the_fix():
    for rule in RULES:
        assert len(rule.why) > 30, rule.id
        assert len(rule.fix) > 10, rule.id


def test_titles_are_sentences_not_ids():
    for rule in RULES:
        assert rule.title == rule.title.strip()
        assert not rule.title.startswith("TLS0")


def test_get_returns_the_rule():
    assert get("TLS001").title


def test_get_unknown_raises():
    import pytest

    with pytest.raises(KeyError):
        get("TLS999")


def test_filter_by_category():
    certs = rules_for(category="certificate")
    assert certs
    assert all(r.category == "certificate" for r in certs)
    assert len(certs) < len(RULES)


def test_filter_by_severity():
    critical = rules_for(severity="critical")
    assert critical
    assert all(r.severity == "critical" for r in critical)


def test_filters_combine():
    both = rules_for(category="cipher", severity="critical")
    assert all(r.category == "cipher" and r.severity == "critical" for r in both)


def test_no_filter_returns_everything():
    assert rules_for() == RULES


def test_by_id_covers_every_rule():
    assert len(BY_ID) == len(RULES)


def test_every_category_is_used():
    used = {r.category for r in RULES}
    assert used == set(CATEGORIES)


def test_critical_rules_are_the_ones_that_end_a_connection():
    # A grading sanity check: if this list grows to twenty rules the grades
    # stop meaning anything.
    critical = [r.id for r in RULES if r.severity == "critical"]
    assert 3 <= len(critical) <= 8, critical
