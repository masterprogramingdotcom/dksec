"""
JSON Report Generator for OmniSec.
"""

import os
import json
from omnisec.models import OmniSecReport


class JsonReporter:
    @staticmethod
    def generate(report: OmniSecReport, output_path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        data = report.to_dict()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return output_path
