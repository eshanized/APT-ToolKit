"""
HTML Report Builder Module for APT Toolkit

Features:
- Professional HTML report generation
- Customizable templates
- Vulnerability visualization
- Thread-safe operation
"""

from typing import Dict, List, Any
from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from src.utils.logger import get_logger
from src.utils.config import config
from src.core.engine import ScanModule, ScanTarget, ScanResult, ScanStatus

logger = get_logger(__name__)

class HTMLBuilder(ScanModule):
    """Professional HTML report builder"""

    def __init__(self):
        super().__init__()
        self.module_name = "html_builder"
        self.reports_dir = Path(config.reporting.html_dir)
        self.template_dir = Path(config.reporting.template_dir)
        self.env = Environment(loader=FileSystemLoader(self.template_dir))
        
        # Setup directories
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def initialize(self) -> None:
        """Initialize builder resources"""
        logger.info(f"Initialized {self.module_name}")

    def cleanup(self) -> None:
        """Cleanup builder resources"""
        logger.info(f"Cleaned up {self.module_name}")

    def validate_target(self, target: ScanTarget) -> bool:
        """Validate target data is appropriate for reporting"""
        return bool(target.metadata.get("results"))

    def _render_template(self, template_name: str, context: Dict[str, Any]) -> str:
        """Render an HTML template with the given context"""
        try:
            template = self.env.get_template(template_name)
            return template.render(context)
        except Exception as e:
            logger.error(f"Failed to render template {template_name}: {str(e)}", exc_info=True)
            raise

    def _generate_report(self, metadata: Dict[str, Any], results: Dict[str, Any]) -> Path:
        """Generate complete HTML report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.reports_dir / f"APT_Report_{timestamp}.html"

        context = {
            "client": metadata.get("client", "N/A"),
            "project": metadata.get("project", "N/A"),
            "date": datetime.now().strftime("%Y-%m-%d"),
            "findings_stats": results.get("findings_stats", {}),
            "vulnerabilities": results.get("vulnerabilities", []),
        }

        try:
            html_content = self._render_template("report_base.html", context)
            report_path.write_text(html_content, encoding="utf-8")
            return report_path
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {str(e)}", exc_info=True)
            raise

    def execute(self, target: ScanTarget) -> ScanResult:
        """
        Generate HTML report from scan results

        Args:
            target: ScanTarget containing report data and metadata

        Returns:
            ScanResult with report generation status
        """
        if not self.validate_target(target):
            logger.error("Invalid HTML generation target")
            return ScanResult(
                target=target,
                data={"error": "Invalid target"},
                status=ScanStatus.FAILED
            )

        try:
            metadata = target.metadata.get("report_metadata", {})
            results = target.metadata.get("results", {})

            logger.info("Generating HTML report from scan results")

            report_path = self._generate_report(metadata, results)

            return ScanResult(
                target=target,
                data={
                    "report_path": str(report_path),
                    "timestamp": datetime.now().isoformat(),
                    "size_bytes": report_path.stat().st_size,
                    "metadata": metadata
                },
                status=ScanStatus.COMPLETED
            )

        except Exception as e:
            logger.error(f"HTML report generation failed: {str(e)}", exc_info=True)
            return ScanResult(
                target=target,
                data={"error": str(e)},
                status=ScanStatus.FAILED
            )

# Module registration
def init_module():
    return HTMLBuilder()