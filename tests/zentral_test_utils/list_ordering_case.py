from datetime import timedelta
from urllib.parse import urlencode

from django.utils import timezone


class ListOrderingCase:
    """Assertions for the ordered, LIMIT/OFFSET paginated API list endpoints."""

    # Scrambled on purpose: the rows are inserted in an order that matches neither ordering
    # direction, so an endpoint that drops ?ordering= on the floor fails both assertions of
    # assert_list_ordering instead of passing one of them by luck.
    _ORDERING_HOURS = (1, 3, 2)

    def given_ordered_rows(self, rows):
        """Backdate every row the endpoint returns, as (instance carrying created_at, response id)
        pairs, and return the response ids in ascending created_at order."""
        now = timezone.now()
        stamped = []
        for hours, (instance, row_id) in zip(self._ORDERING_HOURS, rows, strict=True):
            instance.created_at = now - timedelta(hours=hours)
            instance.save()
            stamped.append((instance.created_at, row_id))
        return [row_id for _, row_id in sorted(stamped)]

    def assert_list_ordering(self, url, ascending_ids):
        for ordering, expected in (("created_at", ascending_ids),
                                   ("-created_at", ascending_ids[::-1])):
            with self.subTest(ordering=ordering):
                response = self.get(f"{url}?{urlencode({'ordering': ordering})}")
                self.assertEqual(response.status_code, 200)
                self.assertEqual([row["id"] for row in response.json()["results"]], expected)

    def assert_list_pages_every_row_once(self, url, ascending_ids, limit=2):
        seen = []
        next_url = f"{url}?{urlencode({'limit': limit})}"
        while next_url:
            response = self.get(next_url)
            self.assertEqual(response.status_code, 200)
            page = response.json()
            self.assertEqual(page["count"], len(ascending_ids))
            seen.extend(row["id"] for row in page["results"])
            next_url = page["next"]
        # no ?ordering=, so this also pins the default ordering of the endpoint
        self.assertEqual(seen, ascending_ids[::-1])
