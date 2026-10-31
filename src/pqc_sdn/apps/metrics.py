"""Start Prometheus metrics exporter."""

from pqc_sdn.logging_config import configure_logging
from pqc_sdn.metrics.exporter import MetricsExporter
from pqc_sdn.settings import get_settings


def main() -> None:
    configure_logging()
    settings = get_settings()
    exporter = MetricsExporter(settings.metrics.host, settings.metrics.port)
    exporter.start()
    input("Metrics running. Press Enter to stop.\n")
    exporter.stop()


if __name__ == "__main__":
    main()
