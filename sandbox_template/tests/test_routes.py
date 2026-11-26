from collections import Counter

import app.main as main_module


def _method_path_keys(app) -> list[tuple[str, str]]:
    keys: list[tuple[str, str]] = []
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if path is None or not methods:
            continue
        keys.extend((method, path) for method in methods)
    return keys


def test_no_shadowed_method_path_routes() -> None:
    """A generated route equal to an existing (method, path) is silently
    shadowed by the earlier router, so the run would grade template code.
    Inspect the fully assembled app (including app/generated_endpoint.py when a
    calibration run drops it in) and fail loudly on duplicates.
    """
    app = main_module.create_app()
    keys = _method_path_keys(app)
    duplicates = sorted(key for key, count in Counter(keys).items() if count > 1)
    assert duplicates == [], f"shadowed (method, path) routes: {duplicates}"
