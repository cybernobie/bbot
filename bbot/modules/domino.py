from .base import BaseModule

import asyncio
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
    options = {"rules": None}
    options_desc = {
        "rules": "Comma-separated list of rules to run. 'None' for all rules (default).",
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
        self.browser_instance = await self.playwright.chromium.launch(headless=True)
        self.logger = logging.getLogger("domino")
        self.preset.core.logger.include_logger(self.logger)
        return True

    async def handle_event(self, event):
        try:
            d = Domino(url=event.data, logger=self.logger, json_mode=True, selected_rules=self.rules)
            results = await d.run(self.playwright, self.browser_instance)
        except DominoError as e:
            self.hugewarning(f"Error running Domino, setting error state: {e}")
            self.errored = True
            return

        if not results:
            return

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
                await self.emit_event(data, "FINDING", event)

    async def finish(self):
        await self.browser_instance.close()
        await self.playwright.stop()
        await asyncio.sleep(0.5)


    async def filter_event(self, event):
        if "status-200" not in event.tags:
            self.debug(f"Rejecting URL {event.data} due to lack of 200 status code. Tags: {event.tags}")
            return False
        return True
