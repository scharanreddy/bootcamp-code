from __future__ import annotations

import json
from typing import Any, Protocol

from pydantic import BaseModel, Field

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


class AdvisorAgentError(RuntimeError):
    """Raised when the Advisor Agent fails to generate an advisory report."""


class ImmediateAction(BaseModel):
    """A single immediate action item."""

    priority: str = Field(..., description="Priority: Critical, High, Medium, or Low.")
    action: str = Field(..., description="Concrete action to take immediately.")
    owner: str = Field(..., description="Team or role responsible for the action.")


class TechnicalRecommendation(BaseModel):
    """A single technical recommendation."""

    recommendation: str = Field(..., description="Technical recommendation.")
    rationale: str = Field(..., description="Why this recommendation matters.")


class DetectionOpportunity(BaseModel):
    """A single detection engineering opportunity."""

    detection_type: str = Field(..., description="Type of detection, e.g. SIEM rule, EDR alert.")
    data_source: str = Field(..., description="Log or telemetry source needed.")
    logic: str = Field(..., description="Detection logic or indicator to alert on.")


class AdvisoryReport(BaseModel):
    """Structured advisory report produced by the Advisor Agent."""

    executive_summary: str
    immediate_actions: list[ImmediateAction]
    technical_recommendations: list[TechnicalRecommendation]
    detection_opportunities: list[DetectionOpportunity]
    long_term_improvements: list[str]


class AdvisoryReportGenerator(Protocol):
    """Abstraction for producing a structured advisory report from context."""

    def generate(self, context: dict[str, Any]) -> AdvisoryReport:
        """Produce a structured advisory report from merged threat context."""
        ...


class AdvisoryRenderer(Protocol):
    """Abstraction for rendering a structured advisory report."""

    def render(self, report: AdvisoryReport) -> str:
        """Render a structured advisory report to a display format."""
        ...


class OpenAIAdvisoryReportGenerator:
    """Generates a structured advisory report from context using an OpenAI model."""

    def __init__(self, model: str | None = None, api_key: str | None = None) -> None:
        self.model = model or settings.openai_model
        self.api_key = api_key or settings.openai_api_key

    def generate(self, context: dict[str, Any]) -> AdvisoryReport:
        """Produce a structured advisory report from merged threat context."""
        try:
            from openai import OpenAI
        except ImportError as error:
            raise AdvisorAgentError(
                "OpenAI SDK is not installed. Install dependencies from requirements.txt."
            ) from error

        client = OpenAI(api_key=self.api_key)
        prompt = (
            "You are a senior security advisor. Using only the facts in the supplied threat, "
            "risk, and industry context, produce a security advisory with five sections: an "
            "executive summary, immediate actions, technical recommendations, detection "
            "opportunities, and long-term improvements. Do not invent facts that are not "
            "supported by the supplied context."
        )

        try:
            response = client.responses.create(
                model=self.model,
                input=[
                    {
                        "role": "system",
                        "content": "You are a senior cyber threat intelligence advisor.",
                    },
                    {
                        "role": "user",
                        "content": f"{prompt}\n\nContext:\n{json.dumps(context)}",
                    },
                ],
                text={
                    "format": {
                        "type": "json_schema",
                        "name": "advisory_report",
                        "schema": self._report_schema(),
                        "strict": True,
                    }
                },
            )
        except Exception as error:
            raise AdvisorAgentError("OpenAI advisory report generation failed") from error

        return AdvisoryReport.model_validate(self._parse_openai_json(response))

    @staticmethod
    def _parse_openai_json(response: Any) -> dict[str, Any]:
        output_text = getattr(response, "output_text", None)
        if not output_text:
            output_text = OpenAIAdvisoryReportGenerator._extract_output_text(response)

        if not output_text:
            raise AdvisorAgentError("OpenAI response did not include advisory JSON")

        try:
            parsed = json.loads(output_text)
        except json.JSONDecodeError as error:
            raise AdvisorAgentError("OpenAI response was not valid JSON") from error

        if not isinstance(parsed, dict):
            raise AdvisorAgentError("OpenAI response JSON was not an object")
        return parsed

    @staticmethod
    def _extract_output_text(response: Any) -> str | None:
        output = getattr(response, "output", None)
        if not output:
            return None

        chunks: list[str] = []
        for item in output:
            for content in getattr(item, "content", []) or []:
                text = getattr(content, "text", None)
                if text:
                    chunks.append(text)
        return "\n".join(chunks) if chunks else None

    @staticmethod
    def _report_schema() -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "executive_summary": {"type": "string"},
                "immediate_actions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "priority": {"type": "string"},
                            "action": {"type": "string"},
                            "owner": {"type": "string"},
                        },
                        "required": ["priority", "action", "owner"],
                    },
                },
                "technical_recommendations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "recommendation": {"type": "string"},
                            "rationale": {"type": "string"},
                        },
                        "required": ["recommendation", "rationale"],
                    },
                },
                "detection_opportunities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "detection_type": {"type": "string"},
                            "data_source": {"type": "string"},
                            "logic": {"type": "string"},
                        },
                        "required": ["detection_type", "data_source", "logic"],
                    },
                },
                "long_term_improvements": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": [
                "executive_summary",
                "immediate_actions",
                "technical_recommendations",
                "detection_opportunities",
                "long_term_improvements",
            ],
        }


class MarkdownAdvisoryRenderer:
    """Renders a structured advisory report as Markdown, using tables where appropriate."""

    def render(self, report: AdvisoryReport) -> str:
        """Render a structured advisory report as a Markdown document."""
        sections = [
            "# Security Advisory Report",
            "",
            "## Executive Summary",
            "",
            report.executive_summary.strip(),
            "",
            "## Immediate Actions",
            "",
            self._render_immediate_actions(report.immediate_actions),
            "",
            "## Technical Recommendations",
            "",
            self._render_technical_recommendations(report.technical_recommendations),
            "",
            "## Detection Opportunities",
            "",
            self._render_detection_opportunities(report.detection_opportunities),
            "",
            "## Long-term Improvements",
            "",
            self._render_bullet_list(report.long_term_improvements),
        ]
        return "\n".join(sections).strip() + "\n"

    @classmethod
    def _render_immediate_actions(cls, actions: list[ImmediateAction]) -> str:
        if not actions:
            return "_No immediate actions identified._"

        rows = "\n".join(
            f"| {cls._escape_cell(a.priority)} | {cls._escape_cell(a.action)} | "
            f"{cls._escape_cell(a.owner)} |"
            for a in actions
        )
        return f"| Priority | Action | Owner |\n| --- | --- | --- |\n{rows}"

    @classmethod
    def _render_technical_recommendations(cls, items: list[TechnicalRecommendation]) -> str:
        if not items:
            return "_No technical recommendations identified._"

        rows = "\n".join(
            f"| {cls._escape_cell(i.recommendation)} | {cls._escape_cell(i.rationale)} |"
            for i in items
        )
        return f"| Recommendation | Rationale |\n| --- | --- |\n{rows}"

    @classmethod
    def _render_detection_opportunities(cls, items: list[DetectionOpportunity]) -> str:
        if not items:
            return "_No detection opportunities identified._"

        rows = "\n".join(
            f"| {cls._escape_cell(i.detection_type)} | {cls._escape_cell(i.data_source)} | "
            f"{cls._escape_cell(i.logic)} |"
            for i in items
        )
        return f"| Detection Type | Data Source | Logic |\n| --- | --- | --- |\n{rows}"

    @classmethod
    def _render_bullet_list(cls, items: list[str]) -> str:
        if not items:
            return "_No long-term improvements identified._"
        return "\n".join(f"- {item}" for item in items)

    @staticmethod
    def _escape_cell(value: str) -> str:
        """Escape characters that would break a Markdown table cell."""
        return value.replace("|", "\\|").replace("\n", " ").strip()


class AdvisorAgent:
    """Agent that synthesizes threat, risk, and industry context into an advisory report."""

    def __init__(
        self,
        generator: AdvisoryReportGenerator,
        renderer: AdvisoryRenderer | None = None,
    ) -> None:
        self.generator = generator
        self.renderer = renderer or MarkdownAdvisoryRenderer()

    def generate_advisory(
        self,
        threat_intelligence: dict[str, Any],
        risk_assessment: dict[str, Any] | None = None,
        industry_intelligence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate a structured and Markdown-rendered advisory report from combined context."""
        context = {
            "threat_intelligence": threat_intelligence,
            "risk_assessment": risk_assessment,
            "industry_intelligence": industry_intelligence,
        }
        logger.debug("Generating advisory report from combined threat context.")

        report = self._generate_report(context)
        markdown = self._render_report(report)

        return {"report": report.model_dump(mode="json"), "markdown": markdown}

    def _generate_report(self, context: dict[str, Any]) -> AdvisoryReport:
        try:
            return self.generator.generate(context)
        except AdvisorAgentError:
            raise
        except Exception as error:
            raise AdvisorAgentError("Unexpected advisory report generation failure") from error

    def _render_report(self, report: AdvisoryReport) -> str:
        try:
            return self.renderer.render(report)
        except Exception as error:
            raise AdvisorAgentError("Unexpected advisory report rendering failure") from error
