import unittest

from threatlens_ai.frontend.pages.analyze_cve import build_timeline_events


class TestBuildTimelineEvents(unittest.TestCase):
    def test_orders_events_oldest_first_and_formats_dates(self) -> None:
        merged = {
            "published_date": "2024-05-01T00:00:00.000",
            "last_modified_date": "2024-06-15T12:30:00",
            "is_known_exploited": True,
            "cisa_kev": {"date_added": "2024-05-20"},
        }

        events = build_timeline_events(merged)

        self.assertEqual(
            [(e["date"], e["label"]) for e in events],
            [
                ("2024-05-01", "Published to NVD"),
                ("2024-05-20", "Added to CISA KEV"),
                ("2024-06-15", "Last modified in NVD"),
            ],
        )

    def test_drops_events_without_usable_dates(self) -> None:
        merged = {
            "published_date": "2024-05-01",
            "last_modified_date": None,
            "cisa_kev": {},
        }

        events = build_timeline_events(merged)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["label"], "Published to NVD")

    def test_returns_empty_list_when_no_dates_present(self) -> None:
        self.assertEqual(build_timeline_events({}), [])

    def test_omits_cisa_event_when_no_date_added(self) -> None:
        merged = {"published_date": "2024-05-01", "cisa_kev": {"date_added": ""}}

        events = build_timeline_events(merged)

        self.assertEqual([e["label"] for e in events], ["Published to NVD"])


if __name__ == "__main__":
    unittest.main()
