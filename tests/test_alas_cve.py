"""Tests for scripts/alas-cve, the AL2023 updateinfo.xml CVE lookup.

The fixture reproduces the layout that makes a line-oriented grep
unreliable: each advisory's description spans lines, but its
references and package list share a physical line with the opening
of the next advisory.  Every test drives the real script as a
subprocess.
"""

import gzip
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, os.pardir, "scripts", "alas-cve")


def advisory(alas, issued, severity, title, cves, packages):
    """One <update> element in AL2023's packed layout."""
    refs = "".join(
        '<reference href="http://cve.mitre.org/cgi-bin/cvename.cgi'
        '?name=%s" title="" id="%s" type="cve" />' % (cve, cve)
        for cve in cves
    )
    pkgs = "".join(
        '<package arch="x86_64" name="%s" release="%s" version="%s" '
        'epoch="0"><filename>%s-%s-%s.x86_64.rpm</filename></package>'
        % (name, rel, ver, name, ver, rel)
        for name, ver, rel in packages
    )
    return (
        '<update status="final" version="1.4" '
        'author="linux-security@amazon.com" type="security" '
        'from="linux-security@amazon.com"><id>%s</id><title>%s</title>'
        '<issued date="%s" /><updated date="%s" />'
        "<severity>%s</severity><description>Package updates.\n\n"
        "%s:\n\tIn the Linux kernel, the following vulnerability has "
        "been resolved:\n\nsome subsystem: fix something (see also "
        "CVE-2026-11111)\n"
        "</description><references>%s</references><pkglist>"
        '<collection short="amazonlinux"><name>Amazon Linux 2023'
        "</name>%s</collection></pkglist></update>"
        % (alas, title, issued, issued, severity, cves[0], refs, pkgs)
    )


def document(*advisories):
    return (
        '<?xml version="1.0" ?>\n<updates>'
        + "".join(advisories)
        + "</updates>\n"
    )


FIXTURE = document(
    advisory(
        "ALAS2023-2026-2106",
        "2026-08-31 09:00:00",
        "Important",
        "Amazon Linux 2023 - ALAS2023-2026-2106: Important priority "
        "package update for kernel6.18",
        ["CVE-2026-68138", "CVE-2026-80901"],
        [
            ("kernel6.18", "6.18.44", "99.149.amzn2023"),
            ("kernel6.18-devel", "6.18.44", "99.149.amzn2023"),
            ("kernel-livepatch-6.18.44-99.149", "1.0", "0.amzn2023"),
        ],
    ),
    advisory(
        "ALAS2023-2026-2107",
        "2026-09-01 09:00:00",
        "Critical",
        "Amazon Linux 2023 - ALAS2023-2026-2107: Important priority "
        "package update for kernel",
        ["CVE-2026-68138"],
        [
            ("kernel", "6.1.182", "227.379.amzn2023"),
            ("kernel-devel", "6.1.182", "227.379.amzn2023"),
            ("kernel-headers", "6.1.182", "227.379.amzn2023"),
        ],
    ),
    advisory(
        "ALAS2023-2026-2108",
        "2026-09-02 09:00:00",
        "Medium",
        "Amazon Linux 2023 - ALAS2023-2026-2108: Medium priority "
        "package update for vim",
        ["CVE-2026-72693", "CVE-2026-55555"],
        [("vim-common", "9.1.1234", "1.amzn2023")],
    ),
    advisory(
        "ALAS2023-2026-2110",
        "2026-07-20 09:00:00",
        "Important",
        "Amazon Linux 2023 - ALAS2023-2026-2110: Important priority "
        "package update for kernel6.12",
        ["CVE-2026-72693", "CVE-2026-74580"],
        [("kernel6.12", "6.12.105", "128.190.amzn2023")],
    ),
    advisory(
        "ALAS2023-2026-2001",
        "2026-07-27 09:00:00",
        "Medium",
        "Amazon Linux 2023 - ALAS2023-2026-2001: Medium priority "
        "package update for kernel",
        ["CVE-2026-72693"],
        [("kernel", "6.1.179", "225.360.amzn2023")],
    ),
)


ROWS_68138 = (
    "ALAS2023-2026-2106\t2026-08-31\tImportant\tkernel6.18"
    "\t6.18.44-99.149.amzn2023\n"
    "ALAS2023-2026-2107\t2026-09-01\tCritical\tkernel"
    "\t6.1.182-227.379.amzn2023\n"
)

ROWS_72693 = (
    "ALAS2023-2026-2110\t2026-07-20\tImportant\tkernel6.12"
    "\t6.12.105-128.190.amzn2023\n"
    "ALAS2023-2026-2001\t2026-07-27\tMedium\tkernel"
    "\t6.1.179-225.360.amzn2023\n"
)


def run(args, stdin=None):
    return subprocess.run(
        [SCRIPT] + args,
        input=stdin,
        stdin=None if stdin is not None else subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
    )


class AlasCveTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.xml = os.path.join(self.work.name, "updateinfo.xml")
        with open(self.xml, "w", encoding="utf-8") as f:
            f.write(FIXTURE)

    def test_cve_maps_to_its_own_advisories_not_its_neighbours(self):
        # A line-oriented grep pairs 2106's references with 2107's
        # package list; the XML parse must not.  The exact rows also
        # prove that kernel-devel, kernel-headers and the livepatch
        # package sharing the advisory add no rows of their own.
        r = run(["CVE-2026-68138", self.xml])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.decode(), ROWS_68138)
        self.assertEqual(r.stderr, b"")

    def test_rows_are_ordered_by_issued_date_before_advisory_id(self):
        # 2110 was issued before 2001 in the fixture, so a sort on the
        # advisory id would put them the other way round.
        r = run(["CVE-2026-72693", self.xml])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.decode(), ROWS_72693)

    def test_default_filter_drops_non_kernel_packages(self):
        # 2108 (vim) references the CVE too and must not appear.
        r = run(["CVE-2026-72693", self.xml])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.decode(), ROWS_72693)

    def test_cve_referenced_only_by_a_filtered_advisory_exits_1(self):
        # Exit 1 like a miss, but say on stderr that an advisory does
        # name the CVE -- that distinction is what a tracker wants.
        r = run(["CVE-2026-55555", self.xml])
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, b"")
        self.assertIn(b"ALAS2023-2026-2108", r.stderr)
        self.assertIn(b"alas-cve:", r.stderr)

    def test_pattern_that_matches_nothing_exits_1(self):
        r = run(["-p", "^nomatch$", "CVE-2026-72693", self.xml])
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, b"")
        self.assertIn(b"alas-cve:", r.stderr)

    def test_package_pattern_option_selects_other_packages(self):
        r = run(["-p", "^vim-", "CVE-2026-72693", self.xml])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout.decode(),
            "ALAS2023-2026-2108\t2026-09-02\tMedium\tvim-common"
            "\t9.1.1234-1.amzn2023\n",
        )

    def test_package_pattern_is_searched_not_fully_matched(self):
        r = run(["-pcommon", "CVE-2026-72693", self.xml])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            [row.split("\t")[3] for row in r.stdout.decode().splitlines()],
            ["vim-common"],
        )

    def test_invalid_package_pattern_exits_2(self):
        r = run(["-p", "(", "CVE-2026-72693", self.xml])
        self.assertEqual(r.returncode, 2)
        self.assertIn(b"alas-cve:", r.stderr)

    def test_matches_references_not_description_text(self):
        # CVE-2026-80901 is a reference of 2106 only, and never in a
        # description; CVE-2026-11111 is in every description and never
        # a reference.
        r = run(["CVE-2026-80901", self.xml])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.decode(), ROWS_68138.splitlines()[0] + "\n")
        r = run(["CVE-2026-11111", self.xml])
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, b"")

    def test_unknown_cve_prints_nothing_and_exits_1(self):
        r = run(["CVE-2026-99999", self.xml])
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, b"")
        self.assertEqual(r.stderr, b"")

    def test_cve_id_match_is_exact_not_prefix(self):
        # CVE-2026-6813 must not match CVE-2026-68138.
        r = run(["CVE-2026-6813", self.xml])
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, b"")

    def test_reads_from_stdin_without_a_file_argument(self):
        r = run(["CVE-2026-68138"], stdin=FIXTURE.encode())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.decode(), ROWS_68138)

    def test_reads_gzip_compressed_input(self):
        gz = os.path.join(self.work.name, "updateinfo.xml.gz")
        with gzip.open(gz, "wb") as f:
            f.write(FIXTURE.encode())
        r = run(["CVE-2026-68138", gz])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.decode(), ROWS_68138)

    def test_dash_file_argument_reads_stdin(self):
        r = run(["CVE-2026-68138", "-"], stdin=FIXTURE.encode())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.decode(), ROWS_68138)

    def test_same_advisory_repeated_in_the_feed_yields_one_row(self):
        with open(self.xml, "w", encoding="utf-8") as f:
            f.write(document(*(FIXTURE.split("<updates>", 1)[1]
                               .rsplit("</updates>", 1)[0],) * 2))
        r = run(["CVE-2026-68138", self.xml])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.decode(), ROWS_68138)

    def test_issued_date_without_the_expected_shape_is_passed_through(self):
        with open(self.xml, "w", encoding="utf-8") as f:
            f.write(document(advisory(
                "ALAS2023-2026-0001", "2026/08/31 09:00:00", "Low", "t",
                ["CVE-2026-68138"], [("kernel", "6.1.1", "1.amzn2023")])))
        r = run(["CVE-2026-68138", self.xml])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout.decode().split("\t")[1], "2026/08/31 09:00:00"
        )

    def test_advisory_without_an_id_is_an_input_error(self):
        with open(self.xml, "w", encoding="utf-8") as f:
            f.write(document(advisory(
                "X", "2026-01-01 00:00:00", "Low", "t",
                ["CVE-2026-68138"], [("kernel", "6.1.1", "1.amzn2023")]
            ).replace("<id>X</id>", "")))
        r = run(["CVE-2026-68138", self.xml])
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, b"")
        self.assertIn(b"alas-cve:", r.stderr)
        self.assertNotIn(b"Traceback", r.stderr)

    def test_corrupt_gzip_body_exits_2_with_a_message(self):
        gz = os.path.join(self.work.name, "updateinfo.xml.gz")
        with gzip.open(gz, "wb") as f:
            f.write(FIXTURE.encode())
        with open(gz, "r+b") as f:
            f.seek(40)
            f.write(b"\xff" * 32)
        r = run(["CVE-2026-68138", gz])
        self.assertEqual(r.returncode, 2)
        self.assertIn(b"alas-cve:", r.stderr)
        self.assertNotIn(b"Traceback", r.stderr)

    def test_closed_stdout_is_not_reported_as_a_miss(self):
        # Piping into head closes our stdout early; that must not
        # surface as a traceback or as exit 1.
        proc = subprocess.Popen(
            [SCRIPT, "CVE-2026-68138", self.xml],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
        )
        proc.stdout.close()
        stderr = proc.stderr.read()
        proc.stderr.close()
        proc.wait(timeout=30)
        self.assertEqual(proc.returncode, 0, stderr)
        self.assertEqual(stderr, b"")

    def test_malformed_xml_exits_2_with_a_message(self):
        with open(self.xml, "w", encoding="utf-8") as f:
            f.write(FIXTURE[: len(FIXTURE) // 2])
        r = run(["CVE-2026-68138", self.xml])
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, b"")
        self.assertIn(b"alas-cve:", r.stderr)

    def test_missing_file_exits_2_with_a_message(self):
        r = run(["CVE-2026-68138", os.path.join(self.work.name, "nope")])
        self.assertEqual(r.returncode, 2)
        self.assertIn(b"alas-cve:", r.stderr)

    def test_bad_cve_argument_exits_2(self):
        r = run(["68138", self.xml])
        self.assertEqual(r.returncode, 2)
        self.assertIn(b"alas-cve:", r.stderr)

    def test_help_exits_0(self):
        for flag in ("-h", "--help"):
            r = run([flag])
            self.assertEqual(r.returncode, 0, flag)
            self.assertIn(b"Usage:", r.stdout)


if __name__ == "__main__":
    unittest.main()
