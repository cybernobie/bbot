from .base import BaseModule

import logging
from domino.DOMino import Domino
from domino.lib.errors import DominoError
from playwright.async_api import async_playwright


class domino(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "safe"]
    meta = {
        "description": "Check for Client-side Web Vulnerabilities with DOMino",
        "created_date": "2025-04-08",
        "author": "@liquidsec",
    }
    module_threads = 3
    deps_pip = ["playwright", "d0m1n0"]
    options = {"rules": None, "suppress_parameter_discovery_reports": True}
    options_desc = {
        "rules": "Comma-separated list of rules to run. 'None' for all rules (default).",
        "suppress_parameter_discovery_reports": "Allow parameter discovery be used to drive rules but supress reporting the discovery itself",
    }

    async def setup(self):
        import asyncio.base_subprocess

        def quiet_transport_del(self):
            try:
                self.close()
            except Exception:
                pass

        asyncio.base_subprocess.BaseSubprocessTransport.__del__ = quiet_transport_del

        # Process rules
        rules = self.config.get("rules")
        if rules is not None:
            self.rules = rules
        else:
            self.rules = None

        self.playwright = await async_playwright().start()

        self.suppress_parameter_discovery_reports = self.config.get("suppress_parameter_discovery_reports", True)
        return True

    @property
    def log(self):
        if self._log is None:
            self._log = logging.getLogger(f"bbot.modules.{self.name}")
        return self._log

    async def handle_event(self, event):
        browser_instance = await self.playwright.chromium.launch(headless=True)
        self.debug(f"Domino starting browser instance for {event.data}")
        try:
            d = Domino(url=event.data, logger=self.log, json_mode=True, selected_rules=self.rules)
            results = await d.run(self.playwright, browser_instance)
        except DominoError as e:
            self.hugewarning(f"Error running Domino, setting error state: {e}")
            self.errored = True
            return

        if results:
            for result in results:
                details = result.get("details", [])
                details_string = f" Details: [{','.join(details)}]" if details else ""

                interactions = result.get("interactions", [])
                interactions_string = f"Interactions: [{','.join(interactions)}]" if interactions else ""

                data = {
                    "description": f"{result['rule_name']}. Description: {result['description']}.{details_string} Detection URL: [{result['detection_url']}] {interactions_string}",
                    "host": str(event.host),
                }

                if result["severity"] == "high":
                    data["severity"] = "high"
                    await self.emit_event(data, "VULNERABILITY", event)
                else:
                    if self.suppress_parameter_discovery_reports and "GET Parameter Access" in result["rule_name"]:
                        continue
                    await self.emit_event(data, "FINDING", event)
        self.debug(f"Domino browsers instance shutting down for {event.data}")
        await browser_instance.close()
        self.debug(f"DOMino browser shutdown complete for {event.data}")

    async def cleanup(self):
        await self.playwright.stop()

    async def filter_event(self, event):
        if "status-200" not in event.tags:
            self.debug(f"Rejecting URL {event.data} due to lack of 200 status code. Tags: {event.tags}")
            return False
        return True
