import unittest

from threatlens_ai.agent.advisor_agent import (
    AdvisorAgent,
    AdvisorAgentError,
    AdvisoryReport,
    DetectionOpportunity,
    ImmediateAction,
    MarkdownAdvisoryRenderer,
    TechnicalRecommendation,
)


def make_report(**overrides: object) -> AdvisoryReport:
    defaults: dict[str, object] = {
        "executive_summary": "A critical, actively exploited vulnerability requires urgent action.",
        "immediate_actions": [
            ImmediateAction(priority="Critical", action="Patch affected systems", owner="IT Ops"),
        ],
        "technical_recommendations": [
            TechnicalRecommendation(
                recommendation="Deploy the vendor patch",
                rationale="Closes the exploited code path",
            ),
        ],
        "detection_opportunities": [
            DetectionOpportunity(
                detection_type="EDR alert",
                data_source="Endpoint telemetry",
                logic="Alert on the known exploitation process chain",
            ),
        ],
        "long_term_improvements": ["Adopt a faster patch management cadence"],
    }
    defaults.update(overrides)
    return AdvisoryReport.model_validate(defaults)


class StubGenerator:
    def __init__(self, report: AdvisoryReport | None = None, error: Exception | None = None) -> None:
        self.report = report or make_report()
        self.error = error
        self.received_context: dict[str, object] | None = None

    def generate(self, context: dict[str, object]) -> AdvisoryReport:
        self.received_context = context
        if self.error:
            raise self.error
        return self.report


class TestMarkdownAdvisoryRenderer(unittest.TestCase):
    def setUp(self) -> None:
        self.renderer = MarkdownAdvisoryRenderer()

    def test_render_includes_all_required_sections(self) -> None:
        markdown = self.renderer.render(make_report())

        for heading in (
            "# Security Advisory Report",
            "## Executive Summary",
            "## Immediate Actions",
            "## Technical Recommendations",
            "## Detection Opportunities",
            "## Long-term Improvements",
        ):
            self.assertIn(heading, markdown)

    def test_render_uses_tables_for_structured_sections(self) -> None:
        markdown = self.renderer.render(make_report())

        self.assertIn("| Priority | Action | Owner |", markdown)
        self.assertIn("| Critical | Patch affected systems | IT Ops |", markdown)
        self.assertIn("| Recommendation | Rationale |", markdown)
        self.assertIn("| Detection Type | Data Source | Logic |", markdown)
        self.assertIn("- Adopt a faster patch management cadence", markdown)

    def test_render_escapes_pipe_characters_in_cells(self) -> None:
        report = make_report(
            immediate_actions=[
                ImmediateAction(priority="High", action="Block IP 1.2.3.4|5.6.7.8", owner="SOC"),
            ]
        )

        markdown = self.renderer.render(report)

        self.assertIn("Block IP 1.2.3.4\\|5.6.7.8", markdown)

    def test_render_handles_empty_sections(self) -> None:
        report = make_report(immediate_actions=[], long_term_improvements=[])

        markdown = self.renderer.render(report)

        self.assertIn("_No immediate actions identified._", markdown)
        self.assertIn("_No long-term improvements identified._", markdown)


class TestAdvisorAgent(unittest.TestCase):
    def test_generate_advisory_returns_report_and_markdown(self) -> None:
        generator = StubGenerator()
        agent = AdvisorAgent(generator)

        result = agent.generate_advisory(
            threat_intelligence={"cve": "CVE-2026-0001"},
            industry_intelligence={"industry": "Healthcare"},
        )

        self.assertIn("report", result)
        self.assertIn("markdown", result)
        self.assertIn("# Security Advisory Report", result["markdown"])
        self.assertEqual(
            generator.received_context,
            {
                "threat_intelligence": {"cve": "CVE-2026-0001"},
                "risk_assessment": None,
                "industry_intelligence": {"industry": "Healthcare"},
            },
        )

    def test_generate_advisory_wraps_generator_failures(self) -> None:
        agent = AdvisorAgent(StubGenerator(error=RuntimeError("boom")))

        with self.assertRaises(AdvisorAgentError):
            agent.generate_advisory(threat_intelligence={"cve": "CVE-2026-0001"})


if __name__ == "__main__":
    unittest.main()
