"""TemplateRenderer — thin Jinja2 wrapper.

Autoescape is on for HTML — every variable rendered with `{{ ... }}` is
HTML-escaped unless explicitly marked safe. CSRF tokens and OAuth
parameters are user-controllable and must not be unescaped.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


class TemplateRenderer:
    def __init__(self, templates_dir: Path) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=select_autoescape(["html"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def render(self, template_name: str, /, **context: object) -> str:
        return self._env.get_template(template_name).render(**context)
