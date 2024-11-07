from bbot.modules.base import BaseModule
from playwright.async_api import async_playwright
import asyncio
from urllib.parse import urlparse, urlunparse
from bs4 import BeautifulSoup

class dom_excavate(BaseModule):
    """
    Load the full DOM of a webpage using Playwright and pass it to excavate for analysis.
    """

    watched_events = ["URL"]
    produced_events = ["URL_UNVERIFIED", "WEB_PARAMETER", "FINDING"]
    flags = ["active", "safe"]
    meta = {
        "description": "Loads the complete DOM of webpages and searches for sensitive information",
        "author": "Aconite33",
    }

    deps_pip = ["playwright", "beautifulsoup4"]
    deps_apt = ["playwright"]

    options = {
        "page_timeout": 30,
        "wait_for": 10,
        "max_depth": 1000000,
        "debug_dom": False,
        "follow_redirects": True,
    }
    
    options_desc = {
        "page_timeout": "Seconds to wait for page load",
        "wait_for": "Additional seconds to wait for dynamic content",
        "max_depth": "Maximum depth for DOM parsing",
        "debug_dom": "Output full DOM content for debugging",
        "follow_redirects": "Follow HTTP redirects",
    }

    def get_option(self, name, default=None):
        """Safely get option value"""
        try:
            return int(self.config.get(name, self.options.get(name, default)))
        except (TypeError, ValueError):
            return self.options.get(name, default)

    def extract_url(self, event):
        """Extract clean URL from BBOT event object"""
        try:
            # Get the raw URL string
            if hasattr(event, 'data'):
                url = event.data
            else:
                url = str(event)
            
            # Clean up the URL
            url = url.replace('URL("', '').replace('")', '')
            
            # Remove any tags or module information
            if ', module=' in url:
                url = url.split(', module=')[0]
                
            self.debug(f"Extracted URL: {url}")
            return url
        except Exception as e:
            self.warning(f"Error extracting URL from event {event}: {e}")
            return None

    def normalize_url(self, url):
        """Normalize URL to ensure it's valid for Playwright"""
        try:
            if not url:
                return None
                
            # Remove any remaining quotes
            url = url.strip('"\'')
            
            parsed = urlparse(url)
            
            # Ensure scheme is either http or https
            if parsed.scheme not in ('http', 'https'):
                self.debug(f"Invalid scheme {parsed.scheme}, defaulting to https")
                parsed = parsed._replace(scheme='https')
            
            # Reconstruct URL
            normalized = urlunparse(parsed)
            self.debug(f"Normalized URL: {url} -> {normalized}")
            return normalized
        except Exception as e:
            self.warning(f"Error normalizing URL {url}: {e}")
            return None

    async def setup(self):
        self.playwright = None
        self.browser = None
        try:
            self.playwright = await async_playwright().start()
            
            # Configure browser launch options
            browser_args = ['--no-sandbox']
            if self.get_option("follow_redirects", True):
                browser_args.extend([
                    '--disable-web-security',
                    '--disable-features=IsolateOrigins,site-per-process',
                ])
            
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=browser_args
            )
            
            self.verbose(f"Initialized Playwright with timeout={self.get_option('page_timeout')}s, wait_for={self.get_option('wait_for')}s")
            return True
        except Exception as e:
            self.error(f"Failed to initialize Playwright: {e}")
            return False

    def create_response_event(self, url, content, status=200, parent_event=None):
        """Create properly formatted HTTP_RESPONSE event"""
        try:
            event_data = {
                "host": urlparse(url).netloc,
                "url": url,
                "status": status,
                "body": content,
                "method": "GET",  # Add required method field
                "header-dict": {
                    "content-type": ["text/html"],
                    "x-dom-excavate": ["true"],
                    "x-dom-length": [str(len(content))],
                },
                "rendered_dom": True
            }
            
            return self.make_event(event_data, "HTTP_RESPONSE", parent=parent_event, tags=["dom-rendered"])
        except Exception as e:
            self.warning(f"Error creating response event: {e}")
            return None

    async def handle_event(self, event):
        if not self.browser:
            return

        # Extract and normalize URL
        raw_url = self.extract_url(event)
        url = self.normalize_url(raw_url)

        if not url:
            self.debug(f"Skipping invalid URL: {event}")
            return

        self.debug(f"Processing: {url}")

        try:
            context = await self.browser.new_context(
                ignore_https_errors=True,
                bypass_csp=True,
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
            )
            
            page = await context.new_page()
            
            # Only log critical browser errors
            page.on("pageerror", lambda err: self.debug(f"Critical browser error: {err}"))
            
            timeout_ms = self.get_option('page_timeout', 30) * 1000

            try:
                response = await page.goto(
                    url,
                    wait_until="networkidle",
                    timeout=timeout_ms
                )
                
                if response:
                    status = response.status
                    self.debug(f"Response status: {status}")
                    
                    # Handle redirects
                    if status in (301, 302, 303, 307, 308):
                        redirect_url = response.headers.get('location')
                        if redirect_url:
                            self.debug(f"Following redirect: {redirect_url}")
                            response = await page.goto(redirect_url, wait_until="networkidle")
                
                # Wait for dynamic content
                wait_time = self.get_option('wait_for', 10)
                await asyncio.sleep(wait_time)
                
            except Exception as e:
                self.debug(f"Navigation failed: {str(e)}")
                await context.close()
                return

            # Get content and analyze
            content = await page.content()
            
            if content:
                content_length = len(content)
                self.debug(f"Retrieved {content_length:,} bytes")
                
                # Create HTTP_RESPONSE event with proper formatting
                dom_event = self.create_response_event(
                    url=url,
                    content=content,
                    status=response.status if response else 200,
                    parent_event=event
                )

                if dom_event:
                    await self.emit_event(dom_event)
                    self.debug(f"Emitted DOM event for {url}")
            else:
                self.debug(f"No content retrieved")

        except Exception as e:
            self.warning(f"Processing error: {str(e)}")
        finally:
            if 'context' in locals():
                await context.close()

    async def cleanup(self):
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()