"""Tests for the versioned configuration registry.

Two rules are being enforced, and they are the reason the module exists rather
than a settings dict.

**A tuned value lives in an artifact or nowhere.** `HygieneTests` is the test that
gives that teeth: it walks the presence package for integer literals matching any
value the active artifact declares, and fails on one it has no stated reason for.
It is a proxy, not a proof - it cannot tell a tuned 15 from a structural 15 - and
the exemption table is where that weakness is written down rather than hidden.

Each exemption pins how many occurrences it covers, and that number is the reason
the table can be trusted. A file-and-value exemption with no count would exempt
every future literal of that value in that file as well as the ones somebody
actually reviewed, so the blind spot would widen quietly every time the file grew.
With the count pinned, an exemption covers exactly what was reviewed when it was
written, a new occurrence fails until the count is raised deliberately, and a
removed one fails until it is lowered - so the table cannot drift out of step with
the code in either direction.

**A confidence figure is only a probability when an artifact says it was measured.**
`CalibrationHonestyTests` pins the shipping artifact as `uncalibrated`, so nothing
downstream can quietly promote an ordering into a probability. When field data
exists, that test is the one that has to be deliberately changed.
"""
import ast
import collections
import json
import pathlib
from types import MappingProxyType

from django.test import SimpleTestCase

from .presence import config

DECLARED = tuple(sorted(config.PARAMETERS))

# Integer literals inside the presence package that coincide with a declared
# parameter value but are structure, not policy. Keyed by file and value, and
# carrying the number of occurrences the reason accounts for. Anything not listed
# here - or one occurrence more than is listed - fails HygieneTests, which is the
# point: a new occurrence has to be justified in this table before it can pass.
LITERAL_EXEMPTIONS = {
    ("proof.py", 2): (4, 
        "wire enumeration values: BIOMETRIC_FAILED, PLATFORM_IOS, "
        "STATUS_SECONDARY and the shift in CAP_RELAY. Each is fixed by the "
        "schema version in the way the schema tag is - a new version may add "
        "values and may never renumber one - so none is tunable and none "
        "belongs in an artifact. Four occurrences, and a fifth fails until "
        "somebody says here what it is."
    ),
    ("codec.py", 2): (5, 
        "schema tag 2 (attendance_proof) and the two-element [tag, version] "
        "prefix every encoding carries, which the decoder measures against in "
        "four places. Both are wire format, fixed by the protocol version, and "
        "neither is tunable."
    ),
    ("proof.py", 3): (4, """
        wire enumeration values again, at the value relay.max_hops happens to
        ship at: BIOMETRIC_CANCELLED, PLATFORM_WEB, STATUS_NOT_VERIFIED and the
        shift in CAP_RANGING. Same argument as the literal 2 above - each is
        fixed by the schema version and may never be renumbered - and the
        collision is with a hop count, which nothing in proof.py counts.
    """),
    ("codec.py", 3): (1, """
        schema tag 3 (origin_sighting). A tag identifies a struct type on the
        wire and is as immutable as the version beside it; renumbering one
        would silently reinterpret every stored encoding.
    """),
    ("origin.py", 3): (1, """
        FLAGS_AD_LEN: the length, type and single flags octet of the mandatory
        AD structure in a BLE advertisement, fixed by the Bluetooth
        specification and not by this system. It is subtracted to work out how
        many octets a frame may use, so it is arithmetic about a wire format.
    """),
    ("fusion.py", 1000): (1, """
        MILLI: the denominator that makes a millinat a thousandth of a nat and a
        per-mille probability a thousandth of one. It is the definition of the
        unit every weight is quoted in, not a quantity of anything, and moving it
        would not retune the layer - it would change what every stored number
        means. The collision is with decide.secondary_millinats, which happens to
        ship at one nat and is a genuinely tunable operating point; nothing in
        fusion.py compares anything to a threshold.
    """),
    ("proof.py", 1000): (1, """
        CONFIDENCE_MILLI_MAX: the same unit denominator seen from the wire side,
        bounding the confidence field a client may claim. Fixed by the encoding
        rather than by policy - a claim is re-derived and never trusted, so the
        bound is about what fits in the field and not about what is acceptable.
    """),
}


def values_with(**overrides):
    """The active artifact's values, with substitutions. For cross-check tests."""
    values = dict(config.active().values)
    values.update(overrides)
    return MappingProxyType(values)


def artifact_with(**overrides):
    return config.Artifact(
        version="test-artifact",
        calibration=config.UNCALIBRATED,
        notes="built by tests_presence_config",
        values=values_with(**overrides),
    )


class ArtifactLoadingTests(SimpleTestCase):
    def test_the_default_version_exists_on_disk(self):
        """A deployment with no PRESENCE_CONFIG_VERSION must still boot."""
        self.assertIn(config.DEFAULT_VERSION, config.available_versions())

    def test_the_shipped_artifact_declares_every_parameter(self):
        artifact = config.load(config.DEFAULT_VERSION)
        self.assertEqual(tuple(sorted(artifact.values)), DECLARED)

    def test_a_missing_version_names_the_ones_that_exist(self):
        with self.assertRaises(config.ConfigError) as caught:
            config.load("2099.01-imaginary")
        self.assertIn(config.DEFAULT_VERSION, str(caught.exception))

    def test_filename_and_contents_must_agree(self):
        """Or a decision cannot be traced back to the parameters that made it."""
        with self.assertRaises(config.ConfigError) as caught:
            config._validate("2026.09-provisional", {"version": "something-else"}, "x.json")
        self.assertIn("filed as", str(caught.exception))

    def test_calibration_is_required_and_closed(self):
        raw = {"version": "v", "parameters": dict(config.active().values)}
        for bad in (None, "", "probably-fine", "FIELD_VALIDATED"):
            with self.subTest(calibration=bad):
                with self.assertRaises(config.ConfigError) as caught:
                    config._validate("v", dict(raw, calibration=bad), "x.json")
                self.assertIn("calibration must be one of", str(caught.exception))

    def test_an_undeclared_parameter_is_refused(self):
        raw = {
            "version": "v",
            "calibration": config.UNCALIBRATED,
            "parameters": dict(config.active().values, **{"challenge.vibes": 3}),
        }
        with self.assertRaises(config.ConfigError) as caught:
            config._validate("v", raw, "x.json")
        self.assertIn("challenge.vibes", str(caught.exception))

    def test_a_missing_parameter_is_refused(self):
        """Adding a parameter must fail loudly until every artifact supplies it."""
        values = dict(config.active().values)
        dropped = values.pop("challenge.step_seconds")
        raw = {"version": "v", "calibration": config.UNCALIBRATED, "parameters": values}
        with self.assertRaises(config.ConfigError) as caught:
            config._validate("v", raw, "x.json")
        self.assertIn("challenge.step_seconds", str(caught.exception))
        self.assertIsNotNone(dropped)

    def test_a_non_object_artifact_is_refused(self):
        for bad in ([], "text", 3, None):
            with self.subTest(value=bad):
                with self.assertRaises(config.ConfigError):
                    config._validate("v", bad, "x.json")

    def test_parameters_must_be_an_object(self):
        with self.assertRaises(config.ConfigError):
            config._validate(
                "v",
                {"version": "v", "calibration": config.UNCALIBRATED, "parameters": []},
                "x.json",
            )

    def test_every_artifact_on_disk_loads(self):
        """Whatever is in the directory must be valid, not just the default."""
        for version in config.available_versions():
            with self.subTest(version=version):
                self.assertEqual(config.load(version).version, version)

    def test_unknown_keys_at_the_top_level_are_ignored_not_fatal(self):
        """Notes and future metadata must not break an older build's loader."""
        raw = {
            "version": "v",
            "calibration": config.UNCALIBRATED,
            "notes": "why these values",
            "author": "someone",
            "parameters": dict(config.active().values),
        }
        self.assertEqual(config._validate("v", raw, "x.json").notes, "why these values")


class ParameterDeclarationTests(SimpleTestCase):
    def test_every_parameter_declares_a_unit_and_a_reason(self):
        """A bound with no stated reason cannot be reviewed, only obeyed."""
        for name in DECLARED:
            p = config.PARAMETERS[name]
            with self.subTest(parameter=name):
                self.assertTrue(p.unit)
                self.assertGreater(len(p.why), 40, "the reason is too thin to review")
                self.assertIsNotNone(p.minimum)
                self.assertIsNotNone(p.maximum)
                self.assertLess(p.minimum, p.maximum)

    def test_the_shipped_values_sit_inside_their_bounds(self):
        artifact = config.load(config.DEFAULT_VERSION)
        for name in DECLARED:
            p = config.PARAMETERS[name]
            with self.subTest(parameter=name):
                self.assertGreaterEqual(artifact[name], p.minimum)
                self.assertLessEqual(artifact[name], p.maximum)

    def test_a_value_below_the_minimum_is_refused(self):
        p = config.PARAMETERS["challenge.step_seconds"]
        with self.assertRaises(config.ConfigError) as caught:
            p.check("challenge.step_seconds", p.minimum - 1)
        self.assertIn("below the declared minimum", str(caught.exception))

    def test_a_value_above_the_maximum_is_refused(self):
        p = config.PARAMETERS["challenge.step_seconds"]
        with self.assertRaises(config.ConfigError) as caught:
            p.check("challenge.step_seconds", p.maximum + 1)
        self.assertIn("above the declared maximum", str(caught.exception))

    def test_a_boolean_is_not_a_count(self):
        """bool subclasses int, so True would otherwise load as 1."""
        p = config.PARAMETERS["challenge.steps_per_epoch"]
        with self.assertRaises(config.ConfigError):
            p.check("challenge.steps_per_epoch", True)

    def test_a_string_is_not_a_count(self):
        p = config.PARAMETERS["challenge.step_seconds"]
        for bad in ("15", None, [15], 15.5):
            with self.subTest(value=bad):
                with self.assertRaises(config.ConfigError):
                    p.check("challenge.step_seconds", bad)

    def test_a_float_parameter_accepts_an_integer_from_json(self):
        """JSON writes 1 where 1.0 was meant; that is not worth failing a load over."""
        p = config.Parameter(float, 0.0, 1.0, "ratio", "a declared float, for this test")
        self.assertEqual(p.check("x", 1), 1.0)
        self.assertIsInstance(p.check("x", 1), float)
        with self.assertRaises(config.ConfigError):
            p.check("x", True)

    def test_a_bool_parameter_accepts_only_a_bool(self):
        p = config.Parameter(bool, None, None, "flag", "a declared bool, for this test")
        self.assertIs(p.check("x", True), True)
        with self.assertRaises(config.ConfigError):
            p.check("x", 1)


class CalibrationHonestyTests(SimpleTestCase):
    def test_the_shipped_artifact_is_not_calibrated(self):
        """Deliberate, and load-bearing.

        Nothing has been fitted against labeled data, so no confidence produced
        under this artifact may be presented as a probability. When field data
        exists this assertion has to be changed on purpose, which is exactly the
        review moment that matters.
        """
        artifact = config.load(config.DEFAULT_VERSION)
        self.assertEqual(artifact.calibration, config.UNCALIBRATED)
        self.assertFalse(artifact.is_calibrated)

    def test_only_field_validation_counts_as_calibrated(self):
        for state in config.CALIBRATION_STATES:
            with self.subTest(calibration=state):
                artifact = config.Artifact("v", state, "", MappingProxyType({}))
                self.assertEqual(artifact.is_calibrated, state == config.FIELD_VALIDATED)

    def test_simulator_fitted_is_not_calibrated(self):
        """The state Phase 3 produces. Measured, but measured against a simulator."""
        artifact = config.Artifact("v", config.SIMULATOR_FITTED, "", MappingProxyType({}))
        self.assertFalse(artifact.is_calibrated)

    def test_the_shipped_notes_say_what_the_numbers_are(self):
        """An uncalibrated artifact has to explain itself, not just declare itself."""
        notes = config.load(config.DEFAULT_VERSION).notes
        self.assertIn("uncalibrated", notes)
        self.assertGreater(len(notes), 200)


class CrossCheckTests(SimpleTestCase):
    def tearDown(self):
        config.set_active(None)

    def test_the_shipped_artifact_is_internally_consistent(self):
        self.assertEqual(config.cross_check(), ())

    def test_a_lifetime_shorter_than_a_step_is_caught(self):
        """No single bound can express this: it is a relationship between two."""
        config.set_active(artifact_with(**{
            "challenge.step_seconds": 30, "challenge.lifetime_seconds": 15,
        }))
        problems = config.cross_check()
        self.assertEqual(len(problems), 1)
        self.assertIn("shorter than one step", problems[0])

    def test_forgetting_a_nonce_before_a_proof_expires_is_caught(self):
        config.set_active(artifact_with(**{
            "proof.max_offline_hours": 48, "proof.nonce_retention_hours": 48,
        }))
        problems = config.cross_check()
        self.assertEqual(len(problems), 1)
        self.assertIn("which is a replay", problems[0])

    def test_all_problems_are_reported_at_once(self):
        """Returned rather than raised, so a review sees the whole picture."""
        config.set_active(artifact_with(**{
            "challenge.step_seconds": 30,
            "challenge.lifetime_seconds": 15,
            "proof.max_offline_hours": 48,
            "proof.nonce_retention_hours": 24,
        }))
        self.assertEqual(len(config.cross_check()), 2)


class ActiveArtifactTests(SimpleTestCase):
    def tearDown(self):
        config.set_active(None)

    def test_active_is_cached_and_replaceable(self):
        first = config.active()
        self.assertIs(config.active(), first)
        installed = artifact_with()
        config.set_active(installed)
        self.assertIs(config.active(), installed)
        config.set_active(None)
        self.assertEqual(config.active().version, config.DEFAULT_VERSION)

    def test_the_version_comes_from_the_environment(self):
        """A staged rollout is two deployments on two artifacts, with no code change."""
        config.set_active(None)
        with self.settings():
            import os

            previous = os.environ.get(config.ENV_VERSION)
            os.environ[config.ENV_VERSION] = "2099.01-imaginary"
            try:
                with self.assertRaises(config.ConfigError):
                    config.active()
            finally:
                if previous is None:
                    os.environ.pop(config.ENV_VERSION, None)
                else:
                    os.environ[config.ENV_VERSION] = previous
                config.set_active(None)

    def test_get_reads_one_parameter(self):
        self.assertEqual(
            config.get("challenge.step_seconds"),
            config.active()["challenge.step_seconds"],
        )

    def test_an_undeclared_parameter_cannot_be_read(self):
        with self.assertRaises(config.ConfigError) as caught:
            config.get("challenge.vibes")
        self.assertIn("not a declared parameter", str(caught.exception))

    def test_values_are_read_only(self):
        """An artifact is a record of a decision; nothing may edit one in place."""
        with self.assertRaises(TypeError):
            config.active().values["challenge.step_seconds"] = 1


class HygieneTests(SimpleTestCase):
    """The teeth behind "a tuned value lives in an artifact or nowhere"."""

    def presence_modules(self):
        """The protocol package, plus the app-level modules that drive it.

        `presence_views.py` and `presence_ledger.py` sit outside `presence/` because
        they are Django-facing, and for a while that put them outside this check as
        well - which is exactly where a tuned number would have gone to hide. An
        earlier draft of the endpoint carried its own observation cap of 32 while the
        wire schema carried 64, and nothing would have caught it.

        `models.py` is deliberately not scanned. Its integers are field widths and
        column lengths, fixed by the encodings they store rather than tuned against
        anything, and a hex digest is 64 characters for the same reason a schema tag
        is immutable. Scanning it would produce a page of exemptions that taught a
        reader nothing.
        """
        root = pathlib.Path(__file__).resolve().parent
        package = [
            p for p in sorted((root / "presence").rglob("*.py"))
            if "config" not in p.parts and "lab" not in p.parts and p.name != "calibrate.py"
        ]
        return package + sorted(root.glob("presence_*.py"))

    def test_no_tuned_value_is_inlined_outside_the_artifact(self):
        """Every declared value, looked for as a literal in every presence module.

        A proxy and not a proof: this cannot distinguish a tuned 15 from a
        structural 15, so small integers that are genuinely structure need an entry
        in LITERAL_EXEMPTIONS with a reason. That table is the honest record of the
        check's blind spot - the alternative is a check nobody trusts, which is the
        same as no check.
        """
        tuned = {v for v in config.active().values.values() if isinstance(v, int)}
        modules = self.presence_modules()
        # A hygiene test that scans nothing, or looks for nothing, passes forever
        # while enforcing nothing. Both halves get asserted before the walk.
        self.assertGreater(len(tuned), 4, "no values to look for")
        self.assertGreater(len(modules), 2, "no modules scanned")
        found = collections.defaultdict(list)
        for path in modules:
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, int)
                    and not isinstance(node.value, bool)
                    and node.value in tuned
                ):
                    found[(path.name, node.value)].append(node.lineno)

        # An exemption covers a stated number of occurrences. Anything past that
        # count is reported, and the lines named are the ones no reason accounts
        # for yet - so raising a count is a deliberate edit rather than a silent
        # consequence of the file getting longer.
        offences = []
        for (filename, value), lines in sorted(found.items()):
            allowed, _ = LITERAL_EXEMPTIONS.get((filename, value), (0, ""))
            for lineno in sorted(lines)[allowed:]:
                offences.append("%s:%d has the literal %d" % (filename, lineno, value))
        self.assertEqual(
            offences,
            [],
            "tuned values must come from presence/config. Move them, or add a "
            "documented entry to LITERAL_EXEMPTIONS if they are structure:\n"
            + "\n".join(offences),
        )

    def test_the_exemption_table_has_no_stale_entries(self):
        """An exemption that no longer matches anything is a lie about the code."""
        for (filename, value), (count, reason) in LITERAL_EXEMPTIONS.items():
            with self.subTest(file=filename, value=value):
                self.assertGreater(len(reason), 40, "state why, reviewably")
                self.assertGreater(count, 0, "an exemption for nothing is not one")
                path = [p for p in self.presence_modules() if p.name == filename]
                self.assertEqual(len(path), 1, "exemption names a module that is gone")
                tree = ast.parse(path[0].read_text(encoding="utf-8"))
                actual = sum(
                    1 for n in ast.walk(tree)
                    if isinstance(n, ast.Constant) and n.value == value
                    and isinstance(n.value, int) and not isinstance(n.value, bool)
                )
                # Equality in both directions. Too many is caught by the test
                # above; too few means the reason describes code that is gone, and
                # a reason nobody can check against the file is not a reason.
                self.assertEqual(
                    actual, count,
                    "the exemption accounts for %d occurrences but %s contains %d"
                    % (count, filename, actual),
                )

    def test_no_presence_module_reads_tuning_from_django_settings(self):
        """The failure mode this avoids is already in the repository.

        `verification.py` reads MIN_FOCAL_DISTANCE_METERS from a setting that no
        settings file defines, so the check it guards has never once run. A
        parameter that lives in an artifact cannot fail that way: a missing one
        refuses to load.
        """
        for path in self.presence_modules():
            source = path.read_text(encoding="utf-8")
            with self.subTest(module=path.name):
                self.assertNotIn("settings.PRESENCE", source)
                self.assertNotIn("getattr(settings", source)

    def test_the_artifact_directory_holds_only_artifacts(self):
        """Nothing but versioned JSON and the loader, so `available_versions` is true."""
        root = pathlib.Path(config.HERE)
        unexpected = sorted(
            p.name for p in root.iterdir()
            if p.is_file() and p.name != "__init__.py"
            and not (p.name.startswith("presence-") and p.suffix == ".json")
        )
        self.assertEqual(unexpected, [])

    def test_each_artifact_file_is_pretty_printed_json(self):
        """Artifacts are reviewed in diffs, so they have to diff readably."""
        for version in config.available_versions():
            path = config.artifact_path(version)
            with self.subTest(version=version):
                text = path.read_text(encoding="utf-8")
                self.assertEqual(json.loads(text)["version"], version)
                self.assertIn("\n  ", text, "artifacts must be indented, not one line")
