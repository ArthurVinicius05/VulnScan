from pathlib import Path

import yaml


def test_production_api_has_no_direct_egress_and_smtp_is_the_only_gateway():
    compose_path = Path(__file__).resolve().parents[2] / "docker-compose.production.yml"
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    services = compose["services"]
    backend_networks = set(services["backend"]["networks"])
    proxy_networks = set(services["smtp-proxy"]["networks"])
    worker_networks = set(services["analysis-worker"]["networks"])
    scanner_networks = set(services["scanner-worker"]["networks"])

    assert "backend_egress" not in backend_networks
    assert "smtp_internal" in backend_networks
    assert proxy_networks == {"smtp_internal", "backend_egress"}
    assert "backend_egress" not in worker_networks
    assert "backend_egress" not in scanner_networks
    assert compose["networks"]["smtp_internal"]["internal"] is True
    assert compose["networks"]["app_internal"]["internal"] is True
    assert services["backend"]["environment"]["SMTP_HOST"] == "smtp-proxy"
    assert services["backend"]["environment"]["SMTP_PORT"] == 2525
