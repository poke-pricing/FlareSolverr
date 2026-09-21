import logging
import re

SENSITIVE_KEYS = ["password"]

class SensitiveDataFilter(logging.Filter):
    def __init__(self, sensitive_keys=None):
        super().__init__()
        self.sensitive_keys = sensitive_keys or SENSITIVE_KEYS
        keys = "|".join(map(re.escape, self.sensitive_keys))
        self.pattern = re.compile(
            rf"(?i)(['\"]?(?:{keys})['\"]?\s*:\s*)(['\"]?[^,'\"\]\}}]+['\"]?)"
        )

    def filter(self, record):
        record.msg = self._redact_value(record.msg)
        if record.args:
            record.args = self._redact_value(record.args)
        return True

    def _redact_value(self, value):
        if isinstance(value, dict):
            return {
                k: ("***" if k.lower() in self.sensitive_keys else self._redact_value(v))
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [self._redact_value(v) for v in value]
        if isinstance(value, tuple):
            return tuple(self._redact_value(v) for v in value)
        if isinstance(value, str):
            return self.pattern.sub(r"\1***", value)
        return value
