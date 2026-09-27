"""Tests for scripts/check-shape, the tracker prose and log size check.

Each fixture is a minimal tracker page.  Every test drives the real
script as a subprocess, and the last test runs it against this
tracker's own page, so `make check` fails once any section outgrows
its budget.
"""

import os
import subprocess
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, os.pardir)
SCRIPT = os.path.join(ROOT, "scripts", "check-shape")
PAGE = os.path.join(ROOT, "site", "content", "_index.md")

# The description each kind of offence carries, anchored so that
# "bullet" cannot match "sub-bullet".
PARAGRAPH = ": paragraph is "
BULLET = ": bullet is "
LEAD = ": log lead is "
SUB_BULLET = ": log sub-bullet is "
ENTRY = ": log entry is "


def lines(n, word="word"):
    """n lines of filler prose, joined with newlines."""
    return "\n".join("%s %d" % (word, i) for i in range(n))


def indented(text, prefix):
    """Indent every line after the first by prefix."""
    first, *rest = text.split("\n")
    return "\n".join([first] + [prefix + line for line in rest])


def page(distro="", log="", summary="", intro="Intro paragraph.",
         log_intro="Intro paragraph.", references="",
         heading="## Patch status"):
    """A tracker page with the given section bodies."""
    return textwrap.dedent("""\
        ---
        title: "x"
        ---

        ## Summary

        {summary}

        {heading}

        {intro}

        | a | b |
        |---|---|
        {{.distros}}

        {distro}

        ## Verification log

        {log_intro}

        {{{{< details summary="Full verification log" >}}}}
        #### Upstream

        {log}
        {{{{< /details >}}}}

        ## References

        {references}
        """).format(summary=summary, heading=heading, intro=intro,
                    distro=distro, log_intro=log_intro, log=log,
                    references=references)


def line_of(text, needle):
    """1-based number of the first line equal to needle."""
    return text.split("\n").index(needle) + 1


class CheckShapeTest(unittest.TestCase):

    def run_script(self, args, cwd=None, data=None):
        return subprocess.run([SCRIPT] + args, capture_output=True,
                              text=data is None, cwd=cwd)

    def run_on(self, text, raw=None):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "_index.md")
            with open(path, "wb") as f:
                f.write(raw if raw is not None else text.encode())
            return subprocess.run([SCRIPT, path], capture_output=True,
                                  text=True)

    def assertClean(self, text):
        result = self.run_on(text)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.returncode, 0, result.stderr)

    def assertFlags(self, text, *kinds):
        """Assert exactly one offence per given kind, in order."""
        result = self.run_on(text)
        self.assertEqual(result.returncode, 1, result.stderr)
        found = result.stdout.splitlines()
        self.assertEqual(len(found), len(kinds), result.stdout)
        for line, kind in zip(found, kinds):
            self.assertIn(kind, line)
        return found

    # Per-distro prose

    def test_clean_page_passes(self):
        distro = "### Debian\n\n" + lines(8) + "\n\n- " + indented(
            lines(8), "  ")
        log = "- **Debian** (via x):\n  - " + indented(lines(6), "    ")
        self.assertClean(page(distro=distro, log=log))

    def test_long_distro_paragraph_is_flagged(self):
        found = self.assertFlags(page(distro="### Debian\n\n" + lines(9)),
                                 PARAGRAPH)
        self.assertIn("9 lines (limit 8)", found[0])

    def test_offence_names_file_and_line(self):
        text = page(distro="### Debian\n\n" + lines(9, "longpara"))
        found = self.assertFlags(text, PARAGRAPH)
        self.assertIn("_index.md:%d:" % line_of(text, "longpara 0"),
                      found[0])

    def test_long_distro_bullet_is_flagged(self):
        distro = "### Debian\n\n- " + indented(lines(9), "  ")
        self.assertFlags(page(distro=distro), BULLET)

    def test_numbered_items_are_bullets(self):
        items = "\n".join("%d. item" % i for i in range(1, 10))
        self.assertClean(page(distro="### Debian\n\n" + items))

    def test_paragraph_ends_at_a_bullet_without_a_blank_line(self):
        distro = "### Debian\n\n" + lines(5) + "\n- " + indented(
            lines(5), "  ")
        self.assertClean(page(distro=distro))

    def test_every_subsection_is_checked(self):
        distro = ("### Debian\n\n" + lines(9) + "\n\n### NixOS\n\n"
                  + lines(9))
        self.assertFlags(page(distro=distro), PARAGRAPH, PARAGRAPH)

    def test_distribution_status_heading_is_recognised(self):
        self.assertFlags(page(distro="### Debian\n\n" + lines(9),
                              heading="## Distribution status"),
                         PARAGRAPH)

    def test_h4_inside_distro_section_still_counts(self):
        distro = "### NixOS\n\n#### Flake users\n\n" + lines(9)
        self.assertFlags(page(distro=distro), PARAGRAPH)

    def test_table_intro_is_ignored(self):
        self.assertClean(page(intro=lines(20),
                              distro="### Debian\n\nshort"))

    def test_other_sections_are_ignored(self):
        self.assertClean(page(summary=lines(20), references=lines(20),
                              distro="### Debian\n\nshort"))

    def test_log_intro_prose_is_ignored(self):
        self.assertClean(page(log_intro=lines(20)))

    def test_backtick_fence_in_distro_section_is_ignored(self):
        distro = "### Debian\n\n```\n" + lines(20) + "\n```"
        self.assertClean(page(distro=distro))

    def test_tilde_fence_in_distro_section_is_ignored(self):
        distro = "### Debian\n\n~~~\n" + lines(20) + "\n~~~"
        self.assertClean(page(distro=distro))

    def test_heading_inside_a_fence_does_not_end_the_section(self):
        distro = ("### Debian\n\n```\n## not a heading\n```\n\n"
                  + lines(9))
        self.assertFlags(page(distro=distro), PARAGRAPH)

    def test_html_comment_is_ignored(self):
        distro = "### Debian\n\n<!--\n" + lines(20) + "\n-->"
        self.assertClean(page(distro=distro))

    def test_blockquote_is_exempt(self):
        quote = "\n".join("> quoted %d" % i for i in range(12))
        self.assertClean(page(distro="### Debian\n\n" + quote))

    # Verification log

    def test_long_lead_is_flagged(self):
        text = page(log="- **Debian** " + indented(lines(5), "  ")
                    + "\n  - one fact")
        found = self.assertFlags(text, LEAD)
        self.assertIn("_index.md:%d:" % line_of(text, "- **Debian** word 0"),
                      found[0])

    def test_four_line_lead_passes(self):
        self.assertClean(page(log="- **Debian** " + indented(lines(4), "  ")
                              + "\n  - one fact"))

    def test_lead_with_blank_line_before_sub_bullets(self):
        self.assertFlags(page(log="- **Debian** " + indented(lines(5), "  ")
                              + "\n\n  - one fact"), LEAD)

    def test_tab_indented_sub_bullet_counts_as_child(self):
        self.assertFlags(page(log="- **Debian** " + indented(lines(5), "  ")
                              + "\n\t- one fact"), LEAD)

    def test_long_sub_bullet_is_flagged(self):
        log = "- **Debian** (via x):\n  - " + indented(lines(7), "    ")
        self.assertFlags(page(log=log), SUB_BULLET)

    def test_six_line_sub_bullet_passes(self):
        log = "- **Debian** (via x):\n  - " + indented(lines(6), "    ")
        self.assertClean(page(log=log))

    def test_lazy_continuation_counts_toward_its_bullet(self):
        log = "- **Debian** (via x):\n  - " + indented(lines(7), "  ")
        self.assertFlags(page(log=log), SUB_BULLET)

    def test_loose_continuation_paragraph_counts_toward_its_bullet(self):
        log = ("- **Debian** (via x):\n  - " + indented(lines(4), "    ")
               + "\n\n    " + indented(lines(3), "    "))
        self.assertFlags(page(log=log), SUB_BULLET)

    def test_childless_entry_uses_the_sub_bullet_limit(self):
        self.assertClean(page(log="- " + indented(lines(6), "  ")))
        self.assertFlags(page(log="- " + indented(lines(7), "  ")), ENTRY)

    def test_third_level_bullets_are_counted_separately(self):
        log = ("- **Debian** (via x):\n  - " + indented(lines(5), "    ")
               + "\n    - " + indented(lines(5), "      "))
        self.assertClean(page(log=log))

    def test_fence_inside_a_sub_bullet_is_ignored(self):
        fenced = "\n".join("  - fake %d" % i for i in range(20))
        log = ("- **Debian** (via x):\n  - one fact\n  ```\n" + fenced
               + "\n  ```")
        self.assertClean(page(log=log))

    def test_every_offence_is_reported(self):
        distro = "### Debian\n\n" + lines(9) + "\n\n" + lines(10)
        log = "- **Debian** (via x):\n  - " + indented(lines(7), "    ")
        self.assertFlags(page(distro=distro, log=log),
                         PARAGRAPH, PARAGRAPH, SUB_BULLET)

    # Usage and input errors

    def test_help_exits_zero(self):
        result = self.run_script(["-h"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Usage:", result.stdout)

    def test_unknown_option_is_a_usage_error(self):
        result = self.run_script(["-x"])
        self.assertEqual(result.returncode, 2)

    def test_too_many_arguments_is_a_usage_error(self):
        result = self.run_script(["a", "b"])
        self.assertEqual(result.returncode, 2)

    def test_missing_file_is_an_input_error(self):
        result = self.run_script(["/nonexistent/_index.md"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("check-shape:", result.stderr)

    def test_page_without_either_section_is_an_input_error(self):
        result = self.run_on("## Summary\n\n" + lines(20) + "\n")
        self.assertEqual(result.returncode, 2)
        self.assertIn("check-shape:", result.stderr)

    def test_invalid_utf8_is_an_input_error(self):
        result = self.run_on(None, raw=b"## Patch status\n\n\xff\xfe\n")
        self.assertEqual(result.returncode, 2)
        self.assertIn("check-shape:", result.stderr)

    def test_default_path_does_not_depend_on_cwd(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_script([], cwd=tmp)
        self.assertNotEqual(result.returncode, 2, result.stderr)

    # The tracker itself

    def test_this_tracker_is_within_budget(self):
        result = self.run_script([PAGE])
        self.assertEqual(result.returncode, 0,
                         "\n" + result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
