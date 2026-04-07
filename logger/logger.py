import logging

class ColorFormatter(logging.Formatter):
    COLORS = {
        "DEBUG":    "\033[90m",   # gris
        "INFO":     "\033[94m",   # bleu
        "WARNING":  "\033[93m",   # jaune
        "ERROR":    "\033[91m",   # rouge
        "CRITICAL": "\033[95m",   # violet
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelname, "")
        message = super().format(record)
        return f"{color}{message}{self.RESET}"


def setup_logger():
    logger = logging.getLogger("API_AUDIT")
    logger.setLevel(logging.INFO)          # ← INFO par défaut, pas DEBUG

    ch = logging.StreamHandler()
    ch.setFormatter(ColorFormatter("%(levelname)s - %(message)s"))
    logger.addHandler(ch)
    logger.propagate = False               # ← évite la double affichage via root logger
    return logger


logger = setup_logger()


def set_verbose(enabled: bool) -> None:
    """Appelé depuis main.py pour activer/désactiver le mode verbose."""
    level = logging.DEBUG if enabled else logging.INFO
    logging.getLogger("API_AUDIT").setLevel(level)


class RequestLogger:
    def __init__(self):
        self.logs = []

    def log(self, method, url, status, response_time):
        self.logs.append({
            "method": method,
            "url":    url,
            "status": status,
            "time":   response_time,
        })

    def get_logs(self):
        return self.logs


request_logger = RequestLogger()