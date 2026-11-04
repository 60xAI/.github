#!/usr/bin/env python3
"""Exercise narrowly reviewed false positives through the actual workflow step."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
NATIVE = Path("jobs/post-processing-rs/src/tools")


def public_route() -> str:
    return "https://xdil-abvj-o7rq.e2.xano.io/api:" + "GYQcK4au" + "/v1/companies"


def source_entries() -> list[tuple[str, str]]:
    # Known source-file digests, split to keep test source free of false findings.
    return [
        (
            "any" + "api_linkedin.py",
            "178de59df4252f5952f9552d1bab870ff" + "ea4c4f74d13a222e8a2a1e3cff9974c",
        ),
        (
            "ca" + "piq.py",
            "d7f3adaa40c4c22233dade2dd80bc5697" + "59e9ff8b6158e42b7b5f2a920ae39d5",
        ),
        (
            "ca" + "piq.py",
            "9403c6cb149085a32292b98fd76a97d93" + "78fa918de0136fc82880f85599e5dca",
        ),
    ]


class NativeFalsePositiveTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name, "repo")
        self.repo.mkdir()
        self.scratch = Path(self.temporary.name, "runner")
        self.scratch.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Security Test")
        self.git("config", "user.email", "test@example.invalid")
        (self.repo / "README.md").write_text("Scanner regression fixture.\n")
        self.commit("Clean base")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args: str) -> str:
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", *args],
            cwd=self.repo,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def commit(self, message: str) -> None:
        self.git("add", ".")
        self.git("commit", "-qm", message)

    def write(self, path: Path, text: str) -> None:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def scan(self, full_history: bool = False) -> tuple[int, list[dict[str, str]]]:
        workflow = (ROOT / ".github/workflows/gitleaks.yml").read_text()
        step = workflow.split("      - name: Scan with central credential rules\n", 1)[
            1
        ]
        block = step.split("        run: |\n", 1)[1].split(
            "      - name: Save paths", 1
        )[0]
        script = "\n".join(
            line[10:] if line.startswith("          ") else line
            for line in block.splitlines()
        )
        output = self.scratch / "output"
        output.write_text("")
        env = {
            "PATH": os.environ["PATH"],
            "RUNNER_TEMP": str(self.scratch),
            "GITHUB_STEP_SUMMARY": str(self.scratch / "summary"),
            "GITHUB_OUTPUT": str(output),
            "BASE_SHA": self.base,
            "HEAD_SHA": self.git("rev-parse", "HEAD").strip(),
            "FULL_HISTORY": "true" if full_history else "false",
        }
        result = subprocess.run(
            ["bash", "-c", script],
            cwd=self.repo,
            env=env,
            text=True,
            capture_output=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.scratch / "gitleaks-redacted.json").exists())
        decoded: object = json.loads(
            (self.scratch / "gitleaks-findings.json").read_text()
        )
        if not isinstance(decoded, list):
            self.fail("Workflow report must be a list")
        report: list[dict[str, str]] = []
        for item in decoded:
            if not isinstance(item, dict) or set(item) != {"path", "rule_id"}:
                self.fail("Workflow report must contain only path/rule pairs")
            path, rule = item["path"], item["rule_id"]
            if not isinstance(path, str) or not isinstance(rule, str):
                self.fail("Workflow report fields must be strings")
            report.append({"path": path, "rule_id": rule})
        return int(output.read_text().strip().removeprefix("result=")), report

    def test_exact_public_route_passes_pr_range_and_full_history(self) -> None:
        # Assemble public metadata so this test source is not itself the finding.
        self.write(NATIVE / "asymmetrix.rs", f'.unwrap_or("{public_route()}")\n')
        self.commit("Known public API route")
        for full_history in (False, True):
            with self.subTest(full_history=full_history):
                self.assertEqual(self.scan(full_history), (0, []))

    def test_exact_three_provenance_values_pass_pr_range_and_full_history(self) -> None:
        self.write(
            NATIVE / "catalog.json",
            "\n".join(f'    "{name}": "{digest}",' for name, digest in source_entries())
            + "\n",
        )
        self.commit("Known source-file fingerprints")
        for full_history in (False, True):
            with self.subTest(full_history=full_history):
                self.assertEqual(self.scan(full_history), (0, []))

    def test_same_file_and_same_line_credentials_still_block(self) -> None:
        generic = hashlib.sha256(b"Synthetic generic credential regression").hexdigest()
        api_key = "sk_" + "live_" + "F" * 43
        name, digest = source_entries()[0]
        metadata = {
            NATIVE / "asymmetrix.rs": f'.unwrap_or("{public_route()}")',
            NATIVE / "catalog.json": f'"{name}": "{digest}",',
        }
        for path, line in metadata.items():
            self.write(path, line + f' api_key="{generic}"; token="{api_key}"\n')
        self.commit("Synthetic credentials beside reviewed metadata")
        for full_history in (False, True):
            with self.subTest(full_history=full_history):
                code, report = self.scan(full_history)
                self.assertEqual(code, 10)
                for path in metadata:
                    for rule in ("generic-api-key", "60x-api-key"):
                        self.assertIn(
                            {"path": path.as_posix(), "rule_id": rule}, report
                        )
                self.assertNotIn(generic, json.dumps(report))
                self.assertNotIn(api_key, json.dumps(report))

    def test_changed_metadata_other_paths_and_other_assignment_names_still_block(
        self,
    ) -> None:
        name, digest = source_entries()[0]
        changed = ("a" if digest[0] != "a" else "b") + digest[1:]
        changed_route = public_route().replace("GYQcK4au", "GYQcK4az")
        cases = [
            (
                NATIVE / "asymmetrix.rs",
                f'.unwrap_or("{changed_route}")\n',
            ),
            (NATIVE / "other.rs", f'.unwrap_or("{public_route()}")\n'),
            (NATIVE / "catalog.json", f'"{name}": "{changed}"\n'),
            (NATIVE / "other.json", f'"{name}": "{digest}"\n'),
            (NATIVE / "catalog.json", f'"api_key": "{digest}"\n'),
        ]
        for index, (path, content) in enumerate(cases):
            with self.subTest(path=path, content_kind=index):
                # Isolate each PR range so an earlier finding cannot mask a miss.
                self.base = self.git("rev-parse", "HEAD").strip()
                self.write(path, content)
                self.commit("Unreviewed value or context")
                code, report = self.scan()
                self.assertEqual(code, 10)
                self.assertIn(
                    {"path": path.as_posix(), "rule_id": "generic-api-key"}, report
                )

    def test_removed_same_file_credential_remains_blocked_in_history(self) -> None:
        path = NATIVE / "asymmetrix.rs"
        metadata = f'.unwrap_or("{public_route()}")\n'
        credential = hashlib.sha256(
            b"Synthetic historical credential regression"
        ).hexdigest()
        self.write(path, metadata + f'api_key="{credential}"\n')
        self.commit("Synthetic credential introduced")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write(path, metadata)
        self.commit("Synthetic credential removed")
        self.assertEqual(self.scan(), (0, []))
        code, report = self.scan(full_history=True)
        self.assertEqual(code, 10)
        self.assertIn({"path": path.as_posix(), "rule_id": "generic-api-key"}, report)


if __name__ == "__main__":
    unittest.main()
