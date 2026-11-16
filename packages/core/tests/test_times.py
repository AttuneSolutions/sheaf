from datetime import date

import pytest

from sheaf_core.times import add_period


@pytest.mark.parametrize(
    ("day", "period", "expected"),
    [
        (date(2026, 11, 26), "P7Y", date(2033, 11, 26)),
        (date(2026, 11, 26), "P1Y6M", date(2028, 5, 26)),
        (date(2026, 1, 31), "P1M", date(2026, 2, 28)),
        (date(2028, 2, 29), "P1Y", date(2029, 2, 28)),
        (date(2026, 11, 26), "P30D", date(2026, 12, 26)),
    ],
)
def test_a_retention_period_is_added_to_a_day(day, period, expected):
    assert add_period(day, period) == expected


def test_a_period_is_whole_years_months_or_days():
    with pytest.raises(ValueError):
        add_period(date(2026, 11, 26), "PT1H")
