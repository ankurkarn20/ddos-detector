from ddos.detect import detect, evaluate, incidents, robust_z, threshold_baseline, windows
from ddos.traffic import Episode, simulate


def run(scenario, duration=300):
    return detect(windows(simulate(duration=duration, seed=1, scenario=scenario)))


def test_robust_z_ignores_outliers_in_history():
    assert abs(robust_z(10, [9, 10, 11, 10, 10, 500])) < 1
    assert robust_z(100, [9, 10, 11, 10, 10]) > 4


def test_each_attack_is_named_and_the_flash_crowd_is_not_an_attack():
    # After the rate threshold's 120 training seconds, as in the demo scenario.
    w = run([Episode("flash_crowd", 130, 160, 1200), Episode("syn_flood", 175, 205, 3000),
             Episode("udp_flood", 220, 240, 2000), Episode("http_flood", 255, 285, 1500)])
    kinds = [i.kind for i in incidents(w)]
    assert kinds == ["surge", "syn_flood", "udp_flood", "http_flood"]
    result = evaluate(w)
    assert result["detector"]["false_alarm_seconds"] == 0
    assert result["threshold"]["false_alarm_seconds"] >= 25      # it flags the flash crowd
    assert result["attack_type_accuracy"] == 1.0


def test_quiet_traffic_raises_nothing():
    w = run([], duration=200)
    assert (w["verdict"] == "normal").all() and not threshold_baseline(w).iloc[120:].any()
