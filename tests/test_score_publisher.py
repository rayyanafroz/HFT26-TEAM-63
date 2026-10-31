import threading
import time

import pytest

from shadowlens.core.score_publisher import ScorePublisher
from shadowlens.models import Band, RiskBlock, ScoreUpdate, TopTool, band_for_score


class FakeInsights:
    def __init__(self):
        self.org_risk = 10
        self.fail = False
        self.reads = 0

    def risk(self):
        if self.fail:
            raise RuntimeError("scoring bug")
        self.reads += 1
        return RiskBlock(org_risk=self.org_risk, band=band_for_score(self.org_risk), compliance_score=100 - self.org_risk)

    def top_tools(self, n=1):
        return [TopTool(tool_id="a|b", risk=self.org_risk, risk_band=band_for_score(self.org_risk))]


class Sink:
    def __init__(self):
        self.messages = []
        self.lock = threading.Lock()

    def __call__(self, kind, payload):
        with self.lock:
            self.messages.append((kind, payload))

    def count(self):
        with self.lock:
            return len(self.messages)


def wait_for(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def make(interval=0.1):
    insights, sink = FakeInsights(), Sink()
    return insights, sink, ScorePublisher(insights, sink, min_interval_s=interval)


def test_the_first_notification_is_sent_at_once():
    insights, sink, publisher = make()
    publisher.notify()
    assert sink.count() == 1
    kind, payload = sink.messages[0]
    assert kind == "score.update" and isinstance(payload, ScoreUpdate)
    assert payload.risk.org_risk == 10 and payload.tool.tool_id == "a|b"
    publisher.close()


def test_a_burst_is_squeezed_into_two_messages_and_the_last_value_wins():
    insights, sink, publisher = make(interval=0.15)
    publisher.notify()                                  # sent at once
    for risk in range(11, 31):                          # a burst of changes inside the interval
        insights.org_risk = risk
        publisher.notify()
    assert sink.count() == 1
    assert wait_for(lambda: sink.count() == 2)          # one trailing update, so nothing is lost
    time.sleep(0.3)
    assert sink.count() == 2
    assert sink.messages[-1][1].risk.org_risk == 30     # it carries the newest score, not an old one
    publisher.close()


def test_a_calm_period_means_the_next_notification_is_immediate_again():
    insights, sink, publisher = make(interval=0.05)
    publisher.notify()
    time.sleep(0.12)
    publisher.notify()
    assert sink.count() == 2
    publisher.close()


def test_publish_now_ignores_the_throttle():
    insights, sink, publisher = make(interval=5)
    publisher.notify()
    publisher.publish_now()
    publisher.publish_now()
    assert sink.count() == 3
    publisher.close()


def test_close_cancels_a_pending_update_and_silences_the_publisher():
    insights, sink, publisher = make(interval=0.2)
    publisher.notify()
    publisher.notify()                                  # schedules a trailing update
    publisher.close()
    time.sleep(0.4)
    assert sink.count() == 1
    publisher.notify()
    publisher.publish_now()
    assert sink.count() == 1


def test_a_scoring_error_is_swallowed():
    insights, sink, publisher = make()
    insights.fail = True
    publisher.notify()                                  # must not raise
    assert sink.count() == 0
    insights.fail = False
    publisher.publish_now()
    assert sink.count() == 1
    publisher.close()


def test_concurrent_notifications_never_exceed_the_rate():
    insights, sink, publisher = make(interval=0.1)
    threads = [threading.Thread(target=lambda: [publisher.notify() for _ in range(50)]) for _ in range(4)]
    started = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    time.sleep(0.3)
    duration = time.monotonic() - started
    assert sink.count() <= int(duration / 0.1) + 2      # 200 notifications became a handful of messages
    publisher.close()


def test_the_score_update_model_follows_the_sot_shape():
    update = ScoreUpdate(risk=RiskBlock(org_risk=52, band=Band.HIGH, compliance_score=48),
                         tool=TopTool(tool_id="python3|openai", risk=52, risk_band=Band.HIGH))
    assert update.model_dump(mode="json") == {
        "risk": {"org_risk": 52, "band": "high", "compliance_score": 48},
        "tool": {"tool_id": "python3|openai", "risk": 52, "risk_band": "high"}}
    assert ScoreUpdate(risk=update.risk).tool is None
    with pytest.raises(Exception):
        ScoreUpdate(risk=update.risk, extra=1)
