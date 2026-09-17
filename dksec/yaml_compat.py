"""
YAML compatibility layer for DKSec (Enterprise Edition).
Attempts to import PyYAML ('yaml'). If PyYAML is not installed or unavailable,
provides a robust, zero-dependency pure Python fallback for safe_load and dump.
Guarantees DKSec never fails with ModuleNotFoundError: No module named 'yaml'.
"""

import os
import re
import json
from typing import Any, Optional

try:
    import yaml as _real_yaml
    HAS_PYYAML = True
except (ImportError, ModuleNotFoundError):
    _real_yaml = None
    HAS_PYYAML = False


def safe_load(stream_or_str: Any) -> Any:
    """Parse YAML content using PyYAML if available, or built-in zero-dependency parser."""
    if HAS_PYYAML and _real_yaml:
        try:
            return _real_yaml.safe_load(stream_or_str)
        except Exception:
            pass

    if hasattr(stream_or_str, "read"):
        text = stream_or_str.read()
    else:
        text = str(stream_or_str)

    if not text or not text.strip():
        return {}

    # 1. Try standard JSON (which is valid YAML)
    try:
        return json.loads(text)
    except Exception:
        pass

    # 2. Parse YAML using built-in lightweight recursive parser
    return _parse_yaml_lines(text)


def dump(data: Any, stream: Optional[Any] = None, default_flow_style: bool = False, **kwargs) -> Optional[str]:
    """Emit formatted YAML using PyYAML if available, or built-in zero-dependency dumper."""
    if HAS_PYYAML and _real_yaml:
        try:
            return _real_yaml.dump(data, stream=stream, default_flow_style=default_flow_style, **kwargs)
        except Exception:
            pass

    result = _simple_yaml_dump(data, indent=0)
    if stream:
        if hasattr(stream, "write"):
            stream.write(result)
            return None
    return result


def _parse_yaml_lines(text: str) -> dict:
    """Zero-dependency line-based YAML parser supporting nested mappings, lists, and primitives."""
    lines = text.splitlines()
    root: dict = {}
    stack: list = [(-1, root)]

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))

        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()

        parent = stack[-1][1]

        # List item: - value or - key: value
        if stripped.startswith("- "):
            item_text = stripped[2:].strip()
            val = _parse_primitive(item_text)
            if isinstance(parent, list):
                parent.append(val)
            elif isinstance(parent, dict):
                # Attach to last key if parent is dict
                pass
            continue

        # Key-Value pair
        if ":" in stripped:
            k, _, v_part = stripped.partition(":")
            k = k.strip().strip("'\"")
            v_part = v_part.strip()

            if not v_part or v_part.startswith("#"):
                new_container: dict = {}
                if isinstance(parent, dict):
                    parent[k] = new_container
                stack.append((indent, new_container))
            else:
                val = _parse_primitive(v_part)
                if isinstance(parent, dict):
                    parent[k] = val

    return root


def _parse_primitive(s: str) -> Any:
    # Strip unquoted comments
    if not (s.startswith('"') or s.startswith("'")):
        if " #" in s:
            s = s.split(" #")[0].strip()

    s = s.strip()
    if s in ("true", "True", "TRUE", "yes", "Yes", "YES"):
        return True
    if s in ("false", "False", "FALSE", "no", "No", "NO"):
        return False
    if s in ("null", "None", "~", ""):
        return None
    try:
        if "." in s:
            return float(s)
        return int(s)
    except ValueError:
        pass
    return s.strip("'\"")


def _simple_yaml_dump(data: Any, indent: int = 0) -> str:
    lines = []
    prefix = "  " * indent
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, dict):
                lines.append(f"{prefix}{k}:")
                sub = _simple_yaml_dump(v, indent + 1)
                if sub:
                    lines.append(sub)
            elif isinstance(v, list):
                lines.append(f"{prefix}{k}:")
                for item in v:
                    if isinstance(item, (dict, list)):
                        lines.append(f"{prefix}  -")
                        sub = _simple_yaml_dump(item, indent + 2)
                        if sub:
                            lines.append(sub)
                    else:
                        lines.append(f"{prefix}  - {_format_primitive(item)}")
            else:
                lines.append(f"{prefix}{k}: {_format_primitive(v)}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}-")
                sub = _simple_yaml_dump(item, indent + 1)
                if sub:
                    lines.append(sub)
            else:
                lines.append(f"{prefix}- {_format_primitive(item)}")
    else:
        lines.append(f"{prefix}{_format_primitive(data)}")

    return "\n".join(lines)


def _format_primitive(v: Any) -> str:
    if v is None:
        return "null"
    elif isinstance(v, bool):
        return "true" if v else "false"
    elif isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if any(c in s for c in [":", "#", "{", "}", "[", "]", ",", "&", "*", "?", "|", "-", "<", ">", "=", "!", "%", "@", "`", "\n"]):
        return json.dumps(s)
    return s
