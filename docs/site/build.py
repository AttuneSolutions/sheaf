"""Build the standard's web page for GitHub Pages: docs/standard.md as one static page, with a
contents list and linkable headings. No scripts, fonts or anything else fetched from elsewhere.

    uv run --no-project --with markdown-it-py==4.3.0 --with mdit-py-plugins==0.7.0 \
        python docs/site/build.py _site
"""

import html
import re
import shutil
import sys
from pathlib import Path
from string import Template

from markdown_it import MarkdownIt
from mdit_py_plugins.anchors import anchors_plugin

DOCS = Path(__file__).resolve().parent.parent
REPOSITORY = "https://github.com/AttuneSolutions/sheaf"


def slug(title: str) -> str:
    """'5.1 The entry envelope' -> '5-1-the-entry-envelope': the section number reads in the URL."""
    return re.sub(r"[^a-z0-9]+", "-", title.lower().replace("`", "")).strip("-")


def build(out: Path) -> None:
    text = (DOCS / "standard.md").read_text(encoding="utf-8")
    title_line, body = text.split("\n", 1)
    title = title_line.removeprefix("# ").strip()

    md = MarkdownIt("commonmark", {"html": False}).enable("table")
    md.use(
        anchors_plugin,
        min_level=2,
        max_level=3,
        slug_func=slug,
        permalink=True,
        permalinkSymbol="#",
        permalinkBefore=False,
    )
    tokens = md.parse(body)

    contents, open_sub = [], False
    for index, token in enumerate(tokens):
        if token.type != "heading_open" or token.tag not in ("h2", "h3"):
            continue
        label = html.escape(tokens[index + 1].content.replace("`", ""))
        link = f'<a href="#{token.attrs["id"]}">{label}</a>'
        if token.tag == "h2":
            if open_sub:
                contents.append("</ol>")
                open_sub = False
            contents.append(("</li>" if contents else "") + f"<li>{link}")
        else:
            if not open_sub:
                contents.append("<ol>")
                open_sub = True
            contents.append(f"<li>{link}</li>")
    contents.append(("</ol>" if open_sub else "") + "</li>")

    rendered = md.renderer.render(tokens, md.options, {})
    rendered = rendered.replace("<table>", '<div class="table"><table>').replace(
        "</table>", "</table></div>"
    )

    page = Template((Path(__file__).parent / "template.html").read_text(encoding="utf-8"))
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(
        page.substitute(
            title=html.escape(title),
            contents="\n".join(contents),
            body=rendered,
            repository=REPOSITORY,
        ),
        encoding="utf-8",
    )
    for name in ("favicon.svg", "sheaf.svg", "sheaf-dark.svg"):
        shutil.copyfile(DOCS / "logo" / name, out / name)
    (out / ".nojekyll").write_text("")


if __name__ == "__main__":
    build(Path(sys.argv[1] if len(sys.argv) > 1 else "_site"))
