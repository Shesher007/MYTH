"""
Unified Advanced Web Agent
=======================
A powerful, Playwright-based browser automation system.
to browse websites, interact with elements, and extract data like a human operator.

Features:
- Async/await native for non-blocking execution
- Human-like interaction patterns (delays, scrolling, typing)
- Stealth mode to bypass bot detection
- DOM extraction with intelligent element labeling
- Screenshot capture for vision-based reasoning
- Session persistence (cookies, localStorage)
- Robust error handling and recovery
"""

import asyncio
import json
import os
import random
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from langchain_core.tools import tool

from myth_config import load_dotenv
from tools.utilities.report import format_industrial_result

load_dotenv()

# Global browser manager instance
_browser_manager: Optional["WebAgentManager"] = None


class WebAgentManager:
    """
    Singleton manager for browser sessions.
    Handles browser lifecycle, page management, and session state.
    """

    def __init__(self):
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self.is_initialized = False

        # Lazy Loading Config
        from config_loader import agent_config

        prefix = agent_config.identity.name.lower()
        self.screenshot_dir = Path(tempfile.gettempdir()) / f"{prefix}_screenshots"
        self.screenshot_dir.mkdir(exist_ok=True)
        self.interaction_history: List[Dict] = []
        self.console_logs: List[str] = []
        self.current_url: str = ""
        self.page_title: str = ""

    async def check_and_install_playwright(self) -> bool:
        """
        Check if Playwright browsers are installed, and install them if missing.
        This provides a zero-config experience for standalone end-users.
        """
        try:
            # 1. Attempt to launch a small headless instance to test installation
            # If this works, we are good.
            test_browser = await self.playwright.chromium.launch(headless=True)
            await test_browser.close()
            return True
        except Exception as e:
            error_str = str(e).lower()
            if (
                "executable doesn't exist" in error_str
                or "playwright install" in error_str
            ):
                from backend import notify_system

                notify_system(
                    "INFO",
                    "Browser Setup",
                    "First-time setup: Downloading Chromium engine... (This may take a minute)",
                )

                print(
                    "🚀 [BROWSER] Playwright binaries missing. Launching automated installer..."
                )
                # Run 'playwright install chromium'
                # We use sys.executable -m playwright to ensure we use the correct environment
                try:
                    process = await asyncio.create_subprocess_exec(
                        sys.executable,
                        "-m",
                        "playwright",
                        "install",
                        "chromium",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await process.communicate()

                    if process.returncode == 0:
                        notify_system(
                            "SUCCESS",
                            "Browser Setup",
                            "Chromium engine installed successfully.",
                        )
                        return True
                    else:
                        notify_system(
                            "ERROR",
                            "Browser Setup",
                            f"Automated installation failed: {stderr.decode()}",
                        )
                        return False
                except Exception as install_err:
                    notify_system(
                        "ERROR",
                        "Browser Setup",
                        f"Installation trigger failed: {install_err}",
                    )
                    return False
            return False

    async def initialize(self, headless: bool = True, stealth: bool = True) -> str:
        """Initialize the browser with optional stealth mode."""
        if self.is_initialized:
            return "Browser already initialized."

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return "ERROR: Playwright not installed. Run: pip install playwright && playwright install chromium"

        try:
            self.playwright = await async_playwright().start()

            # Standalone Hardening: Auto-install Chromium if missing
            await self.check_and_install_playwright()

            # Browser launch arguments for stealth
            launch_args = [
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars",
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-accelerated-2d-canvas",
                "--no-first-run",
                "--no-zygote",
                "--disable-gpu",
            ]

            self.browser = await self.playwright.chromium.launch(
                headless=headless, args=launch_args
            )

            # Context with realistic viewport and user agent
            self.context = await self.browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                locale="en-US",
                timezone_id="America/New_York",
                geolocation={"latitude": 40.7128, "longitude": -74.0060},
                permissions=["geolocation"],
                color_scheme="dark",
            )

            # Stealth JavaScript injections
            if stealth:
                await self.context.add_init_script("""
                    // Override navigator properties
                    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                    Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
                    Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                    
                    // Override chrome property
                    window.chrome = { runtime: {} };
                    
                    // Override permissions
                    const originalQuery = window.navigator.permissions.query;
                    window.navigator.permissions.query = (parameters) => (
                        parameters.name === 'notifications' ?
                        Promise.resolve({ state: Notification.permission }) :
                        originalQuery(parameters)
                    );
                    
                    // Realistic WebGL vendor
                    const getParameter = WebGLRenderingContext.prototype.getParameter;
                    WebGLRenderingContext.prototype.getParameter = function(parameter) {
                        if (parameter === 37445) return 'Intel Inc.';
                        if (parameter === 37446) return 'Intel Iris OpenGL Engine';
                        return getParameter.apply(this, arguments);
                    };
                """)

            self.page = await self.context.new_page()

            # Capture console logs
            self.page.on(
                "console",
                lambda msg: self.console_logs.append(f"[{msg.type}] {msg.text}"),
            )

            # Set default timeout
            self.page.set_default_timeout(30000)

            self.is_initialized = True

            return f"✅ Browser initialized successfully. Mode: {'Headless' if headless else 'Headed'}, Stealth: {'Enabled' if stealth else 'Disabled'}"

        except Exception as e:
            return f"❌ Failed to initialize browser: {str(e)}"

    async def navigate(self, url: str, wait_until: str = "domcontentloaded") -> str:
        """Navigate to a URL with intelligent waiting."""
        if not self.is_initialized:
            init_result = await self.initialize()
            if "ERROR" in init_result or "Failed" in init_result:
                return init_result

        try:
            # Ensure URL has protocol
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            # Human-like pre-navigation delay
            await asyncio.sleep(random.uniform(0.3, 0.8))

            response = await self.page.goto(url, wait_until=wait_until, timeout=60000)

            # Wait for network to be mostly idle
            try:
                await self.page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass  # Continue even if network doesn't fully idle

            self.current_url = self.page.url
            self.page_title = await self.page.title()

            self._log_interaction(
                "navigate", {"url": url, "final_url": self.current_url}
            )

            status = response.status if response else "unknown"
            return f"✅ Navigated to: {self.current_url}\nTitle: {self.page_title}\nStatus: {status}"

        except Exception as e:
            return f"❌ Navigation failed: {str(e)}"

    async def get_page_content(
        self, include_links: bool = True, include_inputs: bool = True
    ) -> str:
        """
        Extract simplified, LLM-friendly page content.
        Returns text content with labeled interactive elements.
        """
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized. Call open_browser first."

        try:
            # Extract page data using JavaScript
            content = await self.page.evaluate("""
                () => {
                    const result = {
                        title: document.title,
                        url: window.location.href,
                        text: '',
                        links: [],
                        inputs: [],
                        buttons: [],
                        headings: []
                    };
                    
                    // Extract main text content
                    const textElements = document.querySelectorAll('p, h1, h2, h3, h4, h5, h6, li, td, th, span, div');
                    const seenText = new Set();
                    textElements.forEach((el, idx) => {
                        const text = el.innerText?.trim();
                        if (text && text.length > 10 && text.length < 500 && !seenText.has(text)) {
                            seenText.add(text);
                        }
                    });
                    result.text = Array.from(seenText).slice(0, 50).join('\\n');
                    
                    // Extract links with labels
                    const links = document.querySelectorAll('a[href]');
                    links.forEach((link, idx) => {
                        const text = link.innerText?.trim() || link.getAttribute('aria-label') || '';
                        const href = link.getAttribute('hre');
                        if (text && href && !href.startsWith('javascript:') && idx < 30) {
                            result.links.push({
                                id: `link_${idx}`,
                                text: text.substring(0, 100),
                                href: href
                            });
                        }
                    });
                    
                    // Extract input fields
                    const inputs = document.querySelectorAll('input, textarea, select');
                    inputs.forEach((input, idx) => {
                        const type = input.getAttribute('type') || input.tagName.toLowerCase();
                        const name = input.getAttribute('name') || input.getAttribute('id') || '';
                        const placeholder = input.getAttribute('placeholder') || '';
                        const label = input.getAttribute('aria-label') || '';
                        if (idx < 20) {
                            result.inputs.push({
                                id: `input_${idx}`,
                                type: type,
                                name: name,
                                placeholder: placeholder,
                                label: label,
                                selector: input.id ? `#${input.id}` : (input.name ? `[name="${input.name}"]` : `input:nth-of-type(${idx + 1})`)
                            });
                        }
                    });
                    
                    // Extract buttons
                    const buttons = document.querySelectorAll('button, [role="button"], input[type="submit"], input[type="button"]');
                    buttons.forEach((btn, idx) => {
                        const text = btn.innerText?.trim() || btn.getAttribute('aria-label') || btn.value || '';
                        if (text && idx < 15) {
                            result.buttons.push({
                                id: `btn_${idx}`,
                                text: text.substring(0, 50),
                                selector: btn.id ? `#${btn.id}` : `button:nth-of-type(${idx + 1})`
                            });
                        }
                    });
                    
                    // Extract headings for structure
                    const headings = document.querySelectorAll('h1, h2, h3');
                    headings.forEach((h, idx) => {
                        const text = h.innerText?.trim();
                        if (text && idx < 10) {
                            result.headings.push({
                                level: h.tagName,
                                text: text.substring(0, 100)
                            });
                        }
                    });
                    
                    return result;
                }
            """)

            # Format for LLM consumption
            output_parts = [
                f"📄 **Page: {content['title']}**",
                f"🔗 URL: {content['url']}",
                "",
                "## Page Structure",
            ]

            if content["headings"]:
                for h in content["headings"]:
                    output_parts.append(f"  {h['level']}: {h['text']}")

            output_parts.append("\n## Main Content (excerpt)")
            output_parts.append(
                content["text"][:1500] + "..."
                if len(content["text"]) > 1500
                else content["text"]
            )

            if include_links and content["links"]:
                output_parts.append("\n## Links")
                for link in content["links"][:15]:
                    output_parts.append(
                        f"  [{link['id']}] {link['text']} → {link['href'][:80]}"
                    )

            if include_inputs and content["inputs"]:
                output_parts.append("\n## Input Fields")
                for inp in content["inputs"]:
                    label = (
                        inp["label"] or inp["placeholder"] or inp["name"] or inp["type"]
                    )
                    output_parts.append(
                        f"  [{inp['id']}] {label} (selector: {inp['selector']})"
                    )

            if content["buttons"]:
                output_parts.append("\n## Buttons")
                for btn in content["buttons"]:
                    output_parts.append(f"  [{btn['id']}] {btn['text']}")

            self._log_interaction("get_content", {"url": self.current_url})

            return "\n".join(output_parts)

        except Exception as e:
            return f"❌ Failed to extract content: {str(e)}"

    async def click(self, selector: str, wait_for_navigation: bool = False) -> str:
        """
        Click an element with human-like behavior.
        Supports CSS selectors, XPath, text content, and labeled IDs from get_page_content.
        """
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        # Use active frame or main page
        target = (
            self.current_frame
            if hasattr(self, "current_frame") and self.current_frame
            else self.page
        )

        try:
            # Convert labeled IDs to actual selectors
            if selector.startswith("link_"):
                idx = int(selector.split("_")[1])
                selector = f"a[href]:nth-of-type({idx + 1})"
            elif selector.startswith("btn_"):
                idx = int(selector.split("_")[1])
                selector = f"button:nth-of-type({idx + 1})"
            elif selector.startswith("input_"):
                idx = int(selector.split("_")[1])
                selector = f"input:nth-of-type({idx + 1})"

            # Try text-based selection if selector looks like text
            element = None
            if not any(c in selector for c in ["#", ".", "[", "/", ":"]):
                # Treat as text content
                try:
                    element = await target.get_by_text(
                        selector, exact=False
                    ).first.element_handle()
                except Exception:
                    try:
                        element = await target.get_by_role(
                            "link", name=selector
                        ).first.element_handle()
                    except Exception:
                        try:
                            element = await target.get_by_role(
                                "button", name=selector
                            ).first.element_handle()
                        except Exception:
                            pass

            if not element:
                # Use the selector directly
                await target.wait_for_selector(selector, timeout=10000)
                element = await target.query_selector(selector)

            if not element:
                return f"❌ Element not found: {selector}"

            # Scroll element into view
            await element.scroll_into_view_if_needed()

            # Human-like delay before click
            await asyncio.sleep(random.uniform(0.1, 0.4))

            if wait_for_navigation:
                # Navigation event is always on the main page/frame context owner? No, frame nav.
                async with target.expect_navigation(timeout=30000):
                    await element.click()
            else:
                await element.click()

            # Wait for any dynamic content
            await asyncio.sleep(random.uniform(0.3, 0.8))

            self.current_url = self.page.url
            self.page_title = await self.page.title()

            self._log_interaction("click", {"selector": selector})

            return f"✅ Clicked: {selector}\nCurrent URL: {self.current_url}"

        except Exception as e:
            return f"❌ Click failed: {str(e)}"

    async def type_text(
        self,
        selector: str,
        text: str,
        clear_first: bool = True,
        press_enter: bool = False,
    ) -> str:
        """
        Type text into an input field with human-like behavior.
        """
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        # Use active frame or main page
        target = (
            self.current_frame
            if hasattr(self, "current_frame") and self.current_frame
            else self.page
        )

        try:
            # Convert labeled IDs
            if selector.startswith("input_"):
                idx = int(selector.split("_")[1])
                selector = f"input:nth-of-type({idx + 1})"

            await self.page.wait_for_selector(selector, timeout=10000)

            if clear_first:
                await target.fill(selector, "")

            # Human-like typing with variable delays
            for char in text:
                await target.type(selector, char, delay=random.randint(30, 100))

            if press_enter:
                await asyncio.sleep(random.uniform(0.2, 0.5))
                await target.press(selector, "Enter")

            self._log_interaction(
                "type",
                {
                    "selector": selector,
                    "text": text[:50] + "..." if len(text) > 50 else text,
                },
            )

            return f"✅ Typed into {selector}: '{text[:50]}{'...' if len(text) > 50 else ''}'"

        except Exception as e:
            return f"❌ Typing failed: {str(e)}"

    async def scroll(self, direction: str = "down", amount: int = 500) -> str:
        """Scroll the page in a direction."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            if direction.lower() == "down":
                await self.page.evaluate(f"window.scrollBy(0, {amount})")
            elif direction.lower() == "up":
                await self.page.evaluate(f"window.scrollBy(0, -{amount})")
            elif direction.lower() == "top":
                await self.page.evaluate("window.scrollTo(0, 0)")
            elif direction.lower() == "bottom":
                await self.page.evaluate(
                    "window.scrollTo(0, document.body.scrollHeight)"
                )

            await asyncio.sleep(random.uniform(0.2, 0.5))

            self._log_interaction("scroll", {"direction": direction, "amount": amount})

            return f"✅ Scrolled {direction} by {amount}px"

        except Exception as e:
            return f"❌ Scroll failed: {str(e)}"

    async def screenshot(self, full_page: bool = False) -> str:
        """Take a screenshot and return the file path."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"screenshot_{timestamp}.png"
            filepath = self.screenshot_dir / filename

            await self.page.screenshot(path=str(filepath), full_page=full_page)

            self._log_interaction(
                "screenshot", {"path": str(filepath), "full_page": full_page}
            )

            return f"✅ Screenshot saved: {filepath}"

        except Exception as e:
            return f"❌ Screenshot failed: {str(e)}"

    async def execute_javascript(self, script: str) -> str:
        """Execute arbitrary JavaScript on the page."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            result = await self.page.evaluate(script)

            self._log_interaction("execute_js", {"script": script[:100]})

            if result is None:
                return "✅ JavaScript executed (no return value)"

            return f"✅ JavaScript result:\n{json.dumps(result, indent=2, default=str)}"

        except Exception as e:
            return f"❌ JavaScript execution failed: {str(e)}"

    async def wait_for_element(self, selector: str, timeout: int = 10000) -> str:
        """Wait for an element to appear on the page."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            target = (
                self.current_frame
                if hasattr(self, "current_frame") and self.current_frame
                else self.page
            )
            await target.wait_for_selector(selector, timeout=timeout)
            return f"✅ Element found: {selector}"
        except Exception:
            return f"❌ Element not found within {timeout}ms: {selector}"

    async def go_back(self) -> str:
        """Navigate back in browser history."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            await self.page.go_back()
            self.current_url = self.page.url
            self.page_title = await self.page.title()

            return f"✅ Navigated back to: {self.current_url}"
        except Exception as e:
            return f"❌ Go back failed: {str(e)}"

    async def go_forward(self) -> str:
        """Navigate forward in browser history."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            await self.page.go_forward()
            self.current_url = self.page.url
            self.page_title = await self.page.title()

            return f"✅ Navigated forward to: {self.current_url}"
        except Exception as e:
            return f"❌ Go forward failed: {str(e)}"

    async def get_cookies(self) -> str:
        """Get all cookies for the current context."""
        if not self.is_initialized or not self.context:
            return "ERROR: Browser not initialized."

        try:
            cookies = await self.context.cookies()
            return f"✅ Cookies:\n{json.dumps(cookies, indent=2)}"
        except Exception as e:
            return f"❌ Failed to get cookies: {str(e)}"

    async def set_cookie(
        self, name: str, value: str, domain: str, path: str = "/"
    ) -> str:
        """Set a cookie."""
        if not self.is_initialized or not self.context:
            return "ERROR: Browser not initialized."

        try:
            await self.context.add_cookies(
                [{"name": name, "value": value, "domain": domain, "path": path}]
            )
            return f"✅ Cookie set: {name}={value}"
        except Exception as e:
            return f"❌ Failed to set cookie: {str(e)}"

    async def download_file(
        self, url: str = None, click_selector: str = None, save_as: str = None
    ) -> str:
        """
        Download a file either by URL or by clicking a download link/button.

        Args:
            url: Direct URL to download (if known)
            click_selector: Selector to click to trigger download (e.g., 'Download' button)
            save_as: Optional custom filename for the downloaded file

        Returns:
            Path to the downloaded file or error message.
        """
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        # Ensure download directory exists
        download_dir = Path(os.getcwd()) / "asset_inventory"
        download_dir.mkdir(parents=True, exist_ok=True)

        try:
            if url:
                # Direct URL download using requests-like approach via page
                import aiohttp

                async with aiohttp.ClientSession() as session:
                    async with session.get(url) as response:
                        if response.status == 200:
                            # Determine filename
                            if save_as:
                                filename = save_as
                            else:
                                # Try to get from Content-Disposition header
                                content_disp = response.headers.get(
                                    "Content-Disposition", ""
                                )
                                if "filename=" in content_disp:
                                    filename = content_disp.split("filename=")[1].strip(
                                        "\"'"
                                    )
                                else:
                                    # Extract from URL
                                    filename = (
                                        url.split("/")[-1].split("?")[0]
                                        or f"download_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                                    )

                            filepath = download_dir / filename
                            content = await response.read()

                            with open(filepath, "wb") as f:
                                f.write(content)

                            self._log_interaction(
                                "download",
                                {
                                    "url": url,
                                    "path": str(filepath),
                                    "size": len(content),
                                },
                            )

                            return f"✅ Downloaded: {filepath}\nSize: {len(content):,} bytes"
                        else:
                            return f"❌ Download failed: HTTP {response.status}"

            elif click_selector:
                # Click-triggered download using Playwright's download handling
                async with self.page.expect_download(timeout=60000) as download_info:
                    # Click the element that triggers the download
                    await self.page.click(click_selector)

                download = await download_info.value

                # Determine save path
                if save_as:
                    filename = save_as
                else:
                    filename = (
                        download.suggested_filename
                        or f"download_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                    )

                filepath = download_dir / filename
                await download.save_as(str(filepath))

                # Get file size
                file_size = filepath.stat().st_size if filepath.exists() else 0

                self._log_interaction(
                    "download",
                    {
                        "selector": click_selector,
                        "path": str(filepath),
                        "size": file_size,
                    },
                )

                return f"✅ Downloaded: {filepath}\nSize: {file_size:,} bytes\nOriginal name: {download.suggested_filename}"

            else:
                return "❌ Error: Provide either 'url' for direct download or 'click_selector' to click a download button."

        except Exception as e:
            return f"❌ Download failed: {str(e)}"

    async def download_all_links(
        self, file_extension: str = None, limit: int = 10
    ) -> str:
        """
        Find and download all files matching a pattern from the current page.

        Args:
            file_extension: Filter by extension (e.g., '.pd', '.zip'). None = all downloadable files.
            limit: Maximum number of files to download. Default 10.

        Returns:
            Summary of downloaded files.
        """
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        download_dir = Path(os.getcwd()) / "asset_inventory"
        download_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Find all download links
            links = await self.page.evaluate(
                """
                (ext) => {
                    const downloadableExtensions = ['.pd', '.zip', '.rar', '.7z', '.tar', '.gz', 
                                                     '.exe', '.msi', '.dmg', '.deb', '.rpm',
                                                     '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                                                     '.txt', '.csv', '.json', '.xml', '.py', '.js'];
                    const links = [];
                    document.querySelectorAll('a[href]').forEach((a, idx) => {
                        const href = a.getAttribute('href');
                        if (!href) return;
                        
                        const lowerHref = href.toLowerCase();
                        const isDownloadable = downloadableExtensions.some(e => lowerHref.includes(e));
                        const hasDownloadAttr = a.hasAttribute('download');
                        
                        if (isDownloadable || hasDownloadAttr) {
                            if (!ext || lowerHref.includes(ext.toLowerCase())) {
                                links.push({
                                    href: href,
                                    text: a.innerText?.trim() || href.split('/').pop(),
                                    download: a.getAttribute('download')
                                });
                            }
                        }
                    });
                    return links;
                }
            """,
                file_extension,
            )

            if not links:
                return "❌ No downloadable files found on this page" + (
                    f" matching '{file_extension}'" if file_extension else ""
                )

            downloaded = []
            failed = []

            for link in links[:limit]:
                try:
                    href = link["href"]
                    # Make absolute URL if needed
                    if href.startswith("/"):
                        href = urljoin(self.current_url, href)
                    elif not href.startswith("http"):
                        href = urljoin(self.current_url, href)

                    result = await self.download_file(url=href)
                    if "✅" in result:
                        downloaded.append(link["text"][:50])
                    else:
                        failed.append(f"{link['text'][:30]}: {result}")
                except Exception as e:
                    failed.append(f"{link['text'][:30]}: {str(e)}")

            summary = "📥 Download Summary:\n"
            summary += f"✅ Successfully downloaded: {len(downloaded)}\n"
            for d in downloaded:
                summary += f"   • {d}\n"

            if failed:
                summary += f"\n❌ Failed: {len(failed)}\n"
                for f in failed[:5]:
                    summary += f"   • {f}\n"

            return summary

        except Exception as e:
            return f"❌ Batch download failed: {str(e)}"

    async def hover(self, selector: str) -> str:
        """Hover over an element."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            await self.page.hover(selector)
            self._log_interaction("hover", {"selector": selector})
            return f"✅ Hovered over: {selector}"
        except Exception as e:
            return f"❌ Hover failed: {str(e)}"

    async def press_key(self, key: str) -> str:
        """Press a specific key (e.g., 'Enter', 'Escape', 'Tab', 'Control+A')."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            await self.page.keyboard.press(key)
            await asyncio.sleep(random.uniform(0.1, 0.3))
            self._log_interaction("press_key", {"key": key})
            return f"✅ Pressed key: {key}"
        except Exception as e:
            return f"❌ Key press failed: {str(e)}"

    async def handle_next_dialog(
        self, accept: bool = True, prompt_text: str = None
    ) -> str:
        """Setup a handler for the NEXT JavaScript dialog (alert/confirm/prompt)."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:

            async def dialog_handler(dialog):
                self._log_interaction(
                    "dialog_event", {"message": dialog.message, "type": dialog.type}
                )

                if prompt_text:
                    await dialog.accept(prompt_text)
                elif accept:
                    await dialog.accept()
                else:
                    await dialog.dismiss()

                # Remove handler after use to avoid side effects
                self.page.remove_listener("dialog", dialog_handler)

            self.page.on("dialog", dialog_handler)
            return f"✅ Ready to handle next dialog (Accept: {accept}, Prompt: {prompt_text})"
        except Exception as e:
            return f"❌ Failed to setup dialog handler: {str(e)}"

    async def get_tabs(self) -> str:
        """List all open tabs (pages)."""
        if not self.is_initialized or not self.context:
            return "ERROR: Browser not initialized."

        pages = self.context.pages
        result = "📑 Open Tabs:\n"
        for i, p in enumerate(pages):
            title = await p.title()
            url = p.url
            active = " (Active)" if p == self.page else ""
            result += f"[{i}] {title[:30]}... - {url[:50]}...{active}\n"
        return result

    async def switch_tab(self, index: int) -> str:
        """Switch the active control to a specific tab index."""
        if not self.is_initialized or not self.context:
            return "ERROR: Browser not initialized."

        pages = self.context.pages
        if 0 <= index < len(pages):
            self.page = pages[index]
            await self.page.bring_to_front()
            self.current_url = self.page.url
            self.page_title = await self.page.title()
            return f"✅ Switched to tab {index}: {self.page_title}"
        else:
            return f"❌ Invalid tab index: {index}. Total tabs: {len(pages)}"

    async def get_element_details(self, selector: str) -> str:
        """Get detailed attributes and state of an element."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            details = await self.page.evaluate(
                """
                (sel) => {
                    const el = document.querySelector(sel);
                    if (!el) return null;
                    
                    const rect = el.getBoundingClientRect();
                    const computed = window.getComputedStyle(el);
                    
                    return {
                        tagName: el.tagName,
                        id: el.id,
                        className: el.className,
                        innerText: el.innerText.substring(0, 200),
                        attributes: Array.from(el.attributes).reduce((acc, attr) => {
                            acc[attr.name] = attr.value;
                            return acc;
                        }, {}),
                        isVisible: (rect.width > 0 && rect.height > 0 && computed.visibility !== 'hidden'),
                        rect: {x: rect.x, y: rect.y, width: rect.width, height: rect.height},
                        color: computed.color,
                        backgroundColor: computed.backgroundColor
                    };
                }
            """,
                selector,
            )

            if not details:
                return f"❌ Element not found: {selector}"

            return (
                f"🔍 Element Details for '{selector}':\n{json.dumps(details, indent=2)}"
            )
        except Exception as e:
            return f"❌ Inspection failed: {str(e)}"

    async def wait_for_network_idle(self, timeout: int = 5000) -> str:
        """Wait for network traffic to settle."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            await self.page.wait_for_load_state("networkidle", timeout=timeout)
            return "✅ Network is idle."
        except Exception as e:
            return f"⚠️ Network did not settle within {timeout}ms: {str(e)}"

    async def reload_page(self, ignore_cache: bool = False) -> str:
        """Reload the current page."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            if ignore_cache:
                # Force reload by clearing cache (workaround) or just standard reload
                await self.page.reload()
            else:
                await self.page.reload()

            await self.page.wait_for_load_state("domcontentloaded")
            self.current_url = self.page.url
            self._log_interaction("reload", {"ignore_cache": ignore_cache})
            return f"✅ Page reloaded: {self.current_url}"
        except Exception as e:
            return f"❌ Reload failed: {str(e)}"

    async def set_local_storage(self, key: str, value: str) -> str:
        """Set a value in localStorage."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            await self.page.evaluate(f"window.localStorage.setItem('{key}', '{value}')")
            return f"✅ LocalStorage set: {key}={value[:20]}..."
        except Exception as e:
            return f"❌ Failed to set localStorage: {str(e)}"

    async def get_local_storage(self, key: str) -> str:
        """Get a value from localStorage."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            value = await self.page.evaluate(f"window.localStorage.getItem('{key}')")
            return (
                f"✅ LocalStorage[{key}]: {value}"
                if value
                else f"ℹ️ LocalStorage key '{key}' is empty/null"
            )
        except Exception as e:
            return f"❌ Failed to get localStorage: {str(e)}"

    async def clear_cookies(self) -> str:
        """Clear all cookies."""
        if not self.is_initialized or not self.context:
            return "ERROR: Browser not initialized."

        try:
            await self.context.clear_cookies()
            return "✅ All cookies cleared."
        except Exception as e:
            return f"❌ Failed to clear cookies: {str(e)}"

    async def select_option(self, selector: str, value: str) -> str:
        """Select an option in a dropdown."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            # Try by value, then label, then index
            await self.page.select_option(selector, value)
            self._log_interaction("select", {"selector": selector, "value": value})
            return f"✅ Selected '{value}' in {selector}"
        except Exception:
            try:
                # Try selecting by label
                await self.page.select_option(selector, label=value)
                return f"✅ Selected label '{value}' in {selector}"
            except Exception as e:
                return f"❌ Select failed: {str(e)}"

    async def check_checkbox(self, selector: str, checked: bool = True) -> str:
        """Check or uncheck a checkbox/radio."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            if checked:
                await self.page.check(selector)
            else:
                await self.page.uncheck(selector)
            self._log_interaction("check", {"selector": selector, "checked": checked})
            return f"✅ set {selector} to {'Checked' if checked else 'Unchecked'}"
        except Exception as e:
            return f"❌ Check action failed: {str(e)}"

    async def get_console_logs(self) -> str:
        """Get recent console logs."""
        if not self.console_logs:
            return "ℹ️ No console logs captured yet."

        # Return last 50 logs
        recent = self.console_logs[-50:]
        return "📜 Console Logs:\n" + "\n".join(recent)

    async def highlight_element(self, selector: str) -> str:
        """Draw a red border around an element."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            await self.page.evaluate("""
                const el = document.querySelector('{selector}');
                if (el) {{
                    el.style.border = '3px solid red';
                    el.style.backgroundColor = 'rgba(255, 0, 0, 0.1)';
                    el.scrollIntoView({{behavior: 'smooth', block: 'center'}});
                }}
            """)
            return f"✅ Highlighted {selector}"
        except Exception as e:
            return f"❌ Highlight failed: {str(e)}"

    async def save_as_pdf(self, path: str = None) -> str:
        """Save page as PDF."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            download_dir = Path(os.getcwd()) / "asset_inventory"
            download_dir.mkdir(parents=True, exist_ok=True)

            if not path:
                filename = f"page_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                filepath = download_dir / filename
            else:
                filepath = Path(path)

            await self.page.pdf(path=str(filepath))
            return f"✅ PDF saved: {filepath}"
        except Exception as e:
            return f"❌ PDF generation failed (Note: PDF only works in Headless mode): {str(e)}"

    async def upload_file(self, selector: str, file_path: str) -> str:
        """Upload a file to an input element."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        # Use active frame or main page
        target = (
            self.current_frame
            if hasattr(self, "current_frame") and self.current_frame
            else self.page
        )

        try:
            # Resolve absolute path
            abs_path = Path(file_path).resolve()
            if not abs_path.exists():
                return f"❌ File not found: {abs_path}"

            # Use the current context (page or frame)
            target = (
                self.current_frame
                if hasattr(self, "current_frame") and self.current_frame
                else self.page
            )

            await target.set_input_files(selector, str(abs_path))
            self._log_interaction(
                "upload", {"selector": selector, "file": str(abs_path)}
            )
            return f"✅ File uploaded to {selector}: {abs_path.name}"
        except Exception as e:
            return f"❌ Upload failed: {str(e)}"

    async def drag_and_drop(self, source: str, target: str) -> str:
        """Drag an element and drop it onto another."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        # Use active frame or main page
        target = (
            self.current_frame
            if hasattr(self, "current_frame") and self.current_frame
            else self.page
        )

        try:
            # Use the current context
            ctx = (
                self.current_frame
                if hasattr(self, "current_frame") and self.current_frame
                else self.page
            )

            await ctx.drag_and_drop(source, target)
            self._log_interaction("drag_drop", {"source": source, "target": target})
            return f"✅ Dragged {source} to {target}"
        except Exception as e:
            return f"❌ Drag & Drop failed: {str(e)}"

    async def switch_to_frame(self, selector_or_name: str = None) -> str:
        """Switch context to an iframe (by name, url, or selector). None resets to main."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            if not selector_or_name:
                self.current_frame = None
                return "✅ Switched back to Main Page context."

            # Try by name/url first
            frame = self.page.frame(name=selector_or_name) or self.page.frame(
                url=selector_or_name
            )

            if not frame:
                # Try finding element handle
                element = await self.page.query_selector(selector_or_name)
                if element:
                    frame = await element.content_frame()

            if frame:
                self.current_frame = frame
                return f"✅ Switched to iframe: {selector_or_name}"
            else:
                return f"❌ Iframe not found: {selector_or_name}"
        except Exception as e:
            return f"❌ Frame switch failed: {str(e)}"

    async def set_geolocation(self, latitude: float, longitude: float) -> str:
        """Set browser geolocation."""
        if not self.is_initialized or not self.context:
            return "ERROR: Browser not initialized."

        try:
            await self.context.set_geolocation(
                {"latitude": latitude, "longitude": longitude}
            )
            await self.context.grant_permissions(["geolocation"])
            return f"✅ Geolocation set to: {latitude}, {longitude}"
        except Exception as e:
            return f"❌ Geolocation failed: {str(e)}"

    async def set_viewport_size(self, width: int, height: int) -> str:
        """Resize the browser viewport."""
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            await self.page.set_viewport_size({"width": width, "height": height})
            return f"✅ Viewport resized to {width}x{height}"
        except Exception as e:
            return f"❌ Resize failed: {str(e)}"

    async def analyze_page_security(self) -> str:
        """
        Perform a comprehensive security scan of the current page.
        Checks: DOM secrets, Comments, Console errors, Insecure forms, Headers (via JS).
        """
        if not self.is_initialized or not self.page:
            return "ERROR: Browser not initialized."

        try:
            # 1. DOM & Comment Analysis
            analysis = await self.page.evaluate("""
                () => {
                    const report = {
                        comments: [],
                        insecure_forms: [],
                        password_fields: [],
                        sensitive_inputs: [],
                        scripts: []
                    };
                    
                    // Extract Comments
                    const iterator = document.createNodeIterator(document.documentElement, NodeFilter.SHOW_COMMENT);
                    let currentNode;
                    while (currentNode = iterator.nextNode()) {
                        const content = currentNode.nodeValue.trim();
                        if (content.length > 0) {
                            report.comments.push(content.substring(0, 100));
                        }
                    }
                    
                    // Check Forms
                    document.querySelectorAll('form').forEach((form, idx) => {
                        const action = form.getAttribute('action') || '';
                        if (action.startsWith('http://')) {
                            report.insecure_forms.push(`Form #${idx} submits to HTTP: ${action}`);
                        }
                    });
                    
                    // Check Inputs
                    document.querySelectorAll('input').forEach((input) => {
                        const type = input.getAttribute('type') || '';
                        const name = input.getAttribute('name') || '';
                        
                        if (type === 'password') {
                            report.password_fields.push(`Password field detected (Name: ${name})`);
                        }
                        
                        if (['key', 'token', 'secret', 'auth'].some(k => name.toLowerCase().includes(k))) {
                            report.sensitive_inputs.push(`Potentially sensitive input: ${name}`);
                        }
                    });
                    
                    // Scripts
                    document.querySelectorAll('script[src]').forEach((s) => {
                        report.scripts.push(s.getAttribute('src'));
                    });
                    
                    return report;
                }
            """)

            # 2. Console Analysis
            error_logs = [
                log
                for log in self.console_logs
                if "error" in log.lower() or "exception" in log.lower()
            ]
            auth_logs = [
                log
                for log in self.console_logs
                if any(k in log.lower() for k in ["key", "token", "auth", "secret"])
            ]

            # 3. Storage Analysis
            local_keys = await self.page.evaluate("Object.keys(localStorage)")
            session_keys = await self.page.evaluate("Object.keys(sessionStorage)")

            # Build Report
            report = [f"🛡️ **Security Scan Report: {self.current_url}**", ""]

            report.append("### 1. Insecure Forms")
            if analysis["insecure_forms"]:
                for f in analysis["insecure_forms"]:
                    report.append(f"❌ {f}")
            else:
                report.append("✅ No insecure HTTP forms found.")

            report.append("\n### 2. Sensitive DOM Elements")
            if analysis["password_fields"]:
                report.append(
                    f"ℹ️ found {len(analysis['password_fields'])} password fields."
                )
            if analysis["sensitive_inputs"]:
                for i in analysis["sensitive_inputs"]:
                    report.append(f"⚠️ {i}")

            report.append("\n### 3. HTML Comments (Potential Leaks)")
            suspicious_comments = [
                c
                for c in analysis["comments"]
                if any(k in c.lower() for k in ["todo", "fix", "key", "admin", "test"])
            ]
            if suspicious_comments:
                for c in suspicious_comments:
                    report.append(f"⚠️ Comment: <!-- {c} -->")
            else:
                report.append(f"ℹ️ {len(analysis['comments'])} benign comments found.")

            report.append("\n### 4. Console Errors & Leaks")
            if error_logs:
                report.append(f"❌ {len(error_logs)} Errors found in console.")
                for entry in error_logs[:5]:
                    report.append(f"   {entry}")
            if auth_logs:
                report.append(f"⚠️ {len(auth_logs)} Auth-related logs found.")
                for entry in auth_logs[:3]:
                    report.append(f"   {entry}")

            report.append("\n### 5. Client Storage")
            report.append(
                f"LocalStorage Keys: {', '.join(local_keys) if local_keys else 'None'}"
            )
            report.append(
                f"SessionStorage Keys: {', '.join(session_keys) if session_keys else 'None'}"
            )

            report.append(f"\n### 6. External Scripts ({len(analysis['scripts'])})")
            for s in analysis["scripts"][:5]:
                report.append(f"• {s}")
            if len(analysis["scripts"]) > 5:
                report.append(f"...and {len(analysis['scripts']) - 5} more.")

            return "\n".join(report)

        except Exception as e:
            return f"❌ Security scan failed: {str(e)}"

    async def close(self) -> str:
        """Close the browser and cleanup resources."""
        try:
            if self.page:
                await self.page.close()
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()

            self.is_initialized = False
            self.page = None
            self.context = None
            self.browser = None
            self.playwright = None

            return "✅ Browser closed successfully."

        except Exception as e:
            return f"❌ Close failed: {str(e)}"

    def _log_interaction(self, action: str, data: Dict):
        """Log an interaction for debugging and replay."""
        self.interaction_history.append(
            {
                "timestamp": datetime.now().isoformat(),
                "action": action,
                "data": data,
                "url": self.current_url,
            }
        )


# --- Tool Functions for LangChain Integration ---


def get_manager() -> WebAgentManager:
    """Get or create the global browser manager."""
    global _browser_manager
    if _browser_manager is None:
        _browser_manager = WebAgentManager()
    return _browser_manager


@tool
async def open_browser(headless: Any = True, stealth: Any = True) -> str:
    """
    Launch a new browser session. MUST be called before any other browser tool.

    Use this tool when:
    - Starting a new task.
    - The browser has been closed or crashed.

    Args:
        headless: Set to True for faster, invisible execution (default). Set False if you need to see the window (e.g., for visual debugging).
        stealth: Set to True (default) to mimic a real human user (bypasses bot detection).
    """
    manager = get_manager()
    return await manager.initialize(headless=headless, stealth=stealth)


@tool
async def navigate_to_url(url: str) -> str:
    """
    Load a specific URL in the active browser tab.

    Use this tool when:
    - You need to visit a website (e.g., 'google.com', 'https://github.com').
    - You want to navigate to a new domain.

    Notes:
    - Automatically handles missing 'https://' prefixes.
    - Waits for the page to load before returning.
    """
    manager = get_manager()
    return await manager.navigate(url)


@tool
async def get_page_content() -> str:
    """
    Scan the current page and return its structure as text.

    Use this tool to:
    - "See" what is on the page.
    - Find IDs for links, buttons, and inputs (e.g., 'link_0', 'btn_2').
    - Read the text content of articles or results.

    Returns:
        Structured text with labeled elements. ALWAYS call this after navigating to a new page to understand the layout.
    """
    manager = get_manager()
    return await manager.get_page_content()


@tool
async def click_element(selector: str, wait_for_navigation: bool = False) -> str:
    """
    Click a button, link, or element on the page.

    Args:
        selector: One of the following:
            - A labeled ID from get_page_content() (BEST OPTION, e.g., 'link_0', 'btn_5').
            - Precise text content (e.g., "Sign Up").
            - A CSS selector (e.g., '#submit', '.nav-item').
        wait_for_navigation: Set to True if the click is expected to load a new page.
    """
    manager = get_manager()
    return await manager.click(selector, wait_for_navigation)


@tool
async def type_into_element(
    selector: str, text: str, clear_first: bool = True, press_enter: bool = False
) -> str:
    """
    Type text into an input field or text area.

    Args:
        selector: The ID of the input (e.g., 'input_0' from get_page_content) or a CSS selector.
        text: The string to type.
        clear_first: True to delete existing text before typing (default).
        press_enter: True to hit 'Enter' key after typing (useful for search bars).
    """
    manager = get_manager()
    return await manager.type_text(selector, text, clear_first, press_enter)


@tool
async def scroll_page(direction: str = "down", amount: int = 500) -> str:
    """
    Scroll the viewport to see more content.

    Use this when:
    - The content you need is "below the fold".
    - You are reading a long article or infinite-scroll feed.

    Args:
        direction: 'down', 'up', 'top', or 'bottom'.
        amount: Pixels to scroll (for up/down).
    """
    manager = get_manager()
    return await manager.scroll(direction, amount)


@tool
async def take_screenshot(full_page: Any = False) -> str:
    """
    Capture an image of the current page state.

    Use this when:
    - You need to visually analyze the page layout.
    - You want to confirm an action was successful (e.g., "Show me the payment receipt").
    - Debugging why an element isn't clickable.

    Args:
        full_page: True for the entire scrollable page, False for just the visible area.
    """
    manager = get_manager()
    return await manager.screenshot(full_page)


@tool
async def execute_js(script: str) -> str:
    """
    Run custom JavaScript on the page.

    Use this for:
    - Extracting data that isn't in the DOM text (e.g., specific meta tags).
    - Manipulating the page state directly (e.g., "window.scrollTo(0, 1000)").
    - Bypassing complex UI restrictions.

    Args:
        script: Valid JavaScript code. The return value will be passed back to you.
    """
    manager = get_manager()
    return await manager.execute_javascript(script)


@tool
async def browser_go_back() -> str:
    """
    Simulate clicking the browser's "Back" button.
    Useful for returning to search results after visiting a link.
    """
    manager = get_manager()
    return await manager.go_back()


@tool
async def browser_go_forward() -> str:
    """
    Simulate clicking the browser's "Forward" button.
    """
    manager = get_manager()
    return await manager.go_forward()


@tool
async def close_browser() -> str:
    """
    End the browser session and free up resources.
    Call this when the task is completely finished.
    """
    manager = get_manager()
    return await manager.close()


@tool
async def wait_for_page_element(selector: str, timeout: int = 10000) -> str:
    """
    Pause execution until a specific element appears.

    Use this when:
    - You clicked a button and are waiting for a popup.
    - The page loads content dynamically (AJAX).

    Args:
        selector: CSS selector to wait for.
        timeout: Max wait time in ms (default 10s).
    """
    manager = get_manager()
    return await manager.wait_for_element(selector, timeout)


@tool
async def download_file(
    url: str = None, click_selector: str = None, save_as: str = None
) -> str:
    """
    Download a single file to the agent's storage.

    Args:
        url: Direct URL to the file (e.g., 'http://example.com/doc.pdf').
        click_selector: If the link hides the URL, provide the button selector here to click-and-download.
        save_as: Custom filename (optional).
    """
    manager = get_manager()
    return await manager.download_file(url, click_selector, save_as)


@tool
async def download_all_links(file_extension: str = None, limit: int = 10) -> str:
    """
    Batch download multiple files from the current page.

    Use this for:
    - Scraper tasks (e.g., "Download all financial reports").
    - Grabbing every image or PDF.

    Args:
        file_extension: Filter (e.g., '.pd', '.csv'). Leave None for everything.
        limit: Max files to download (default 10).
    """
    manager = get_manager()
    return await manager.download_all_links(file_extension, limit)


@tool
async def hover_element(selector: str) -> str:
    """
    Move the mouse cursor over an element without clicking.

    Use this for:
    - Opening dropdown menus.
    - Revealing tooltips or hidden actions.
    - Triggering hover effects.

    Args:
        selector: CSS selector or text of the target.
    """
    manager = get_manager()
    return await manager.hover(selector)


@tool
async def press_key(key: str) -> str:
    """
    Press a specific keyboard key.

    Use this for:
    - Submitting forms ('Enter').
    - Closing modals ('Escape').
    - Navigating games or canvas apps ('ArrowRight').
    - Shortcuts ('Control+A').

    Args:
        key: Key name.
    """
    manager = get_manager()
    return await manager.press_key(key)


@tool
async def handle_next_dialog(
    accept: Any = True, prompt_text: str = None, **kwargs
) -> str:
    """
    Prepare to handle the NEXT JavaScript popup (alert/confirm/prompt).
    **CRITICAL**: You must call this tool BEFORE performing the action that triggers the popup.

    Args:
        accept: True to click "OK/Yes", False to click "Cancel/No".
        prompt_text: Text to type into the prompt field (if applicable).
    """
    manager = get_manager()
    return await manager.handle_next_dialog(accept, prompt_text)


@tool
async def get_browser_tabs() -> str:
    """
    Get a list of all currently open browser tabs/pages.
    Returns: IDs and Titles of all tabs.
    """
    manager = get_manager()
    return await manager.get_tabs()


@tool
async def switch_browser_tab(index: int) -> str:
    """
    Switch the active control to a different open tab.

    Args:
        index: The index of the tab (get this from get_browser_tabs).
    """
    manager = get_manager()
    return await manager.switch_tab(index)


@tool
async def get_element_details(selector: str) -> str:
    """
    Inspect an element deeply to get its attributes, styles, and state.

    Use this when:
    - You need to know if an element is visible or hidden.
    - You need to extract a specific attribute (e.g., 'data-id', 'src').
    - You are debugging layout issues.

    Args:
        selector: CSS selector.
    """
    manager = get_manager()
    return await manager.get_element_details(selector)


@tool
async def wait_for_network_idle(timeout: Any = 5000) -> str:
    """
    Ensure the page has finished loading (including background network requests).

    Use this when:
    - Content is missing after a navigation.
    - You are dealing with a heavy Single Page Application (React/Vue/Angular).

    Args:
        timeout: Max wait in ms (default 5000).
    """
    manager = get_manager()
    return await manager.wait_for_network_idle(timeout)


@tool
async def reload_page(ignore_cache: Any = False, **kwargs) -> str:
    """
    Refresh the current page.

    Use this when:
    - The page seems stuck or broken.
    - You want to reset the state of a form.
    - Capturing a fresh network state.

    Args:
        ignore_cache: Force a hard reload from the server (ctrl+F5 style).
    """
    manager = get_manager()
    return await manager.reload_page(ignore_cache)


@tool
async def set_local_storage(key: str, value: str) -> str:
    """
    Inject a key-value pair into window.localStorage.
    Useful for setting feature flags, session tokens, or preferences bypassing the UI.
    """
    manager = get_manager()
    return await manager.set_local_storage(key, value)


@tool
async def get_local_storage(key: str) -> str:
    """
    Read a value from window.localStorage.
    """
    manager = get_manager()
    return await manager.get_local_storage(key)


@tool
async def clear_cookies() -> str:
    """
    Delete all cookies for the current domain.
    Effectively "logs out" the user and resets tracking.
    """
    manager = get_manager()
    return await manager.clear_cookies()


@tool
async def select_dropdown_option(selector: str, value: str) -> str:
    """
    Choose an option from a standard HTML <select> dropdown.

    Args:
        selector: CSS selector of the select element.
        value: The text (label) or "value" attribute to match.
    """
    manager = get_manager()
    return await manager.select_option(selector, value)


@tool
async def toggle_checkbox(selector: str, checked: bool = True) -> str:
    """
    Set the state of a checkbox or radio button.

    Args:
        selector: CSS selector.
        checked: True = check it, False = uncheck it.
    """
    manager = get_manager()
    return await manager.check_checkbox(selector, checked)


@tool
async def highlight_page_element(selector: str) -> str:
    """
    Draw a bright red border around an element.
    Use this to verify your CSS selector matches the correct item before clicking.
    """
    manager = get_manager()
    return await manager.highlight_element(selector)


@tool
async def save_page_as_pdf(path: str = None) -> str:
    """
    Render the current page as a PDF file.
    Note: Can fail if the browser isn't in Headless mode.
    """
    manager = get_manager()
    return await manager.save_as_pdf(path)


@tool
async def upload_file_to_selector(selector: str, file_path: str) -> str:
    """
    Upload a local file to an <input type="file"> element.

    Args:
        selector: CSS selector of the input field.
        file_path: Absolute path to the file on your machine.
    """
    manager = get_manager()
    return await manager.upload_file(selector, file_path)


@tool
async def drag_element_to_target(source_selector: str, target_selector: str) -> str:
    """
    Perform a drag-and-drop gesture.
    Moves 'source' element and drops it centered on 'target' element.
    """
    manager = get_manager()
    return await manager.drag_and_drop(source_selector, target_selector)


@tool
async def switch_to_iframe(selector_or_name: str = None) -> str:
    """
    Change the "active processing context" to an iframe.

    CRITICAL:
    - If an element is inside an iframe (like an ad, payment form, or chat), you MUST call this first.
    - All subsequent clicks/types will target that iframe.
    - Call with None to escape back to the main page.

    Args:
        selector_or_name: The iframe's 'name', 'src' URL, or CSS selector.
    """
    manager = get_manager()
    return await manager.switch_to_frame(selector_or_name)


@tool
async def set_browser_geolocation(latitude: Any, longitude: Any) -> str:
    """
    Overwrite the browser's geolocation coordinates.
    Sites will think the user is at this lat/long.
    """
    manager = get_manager()
    return await manager.set_geolocation(latitude, longitude)


@tool
async def set_browser_viewport(width: int, height: int) -> str:
    """
    Resize the browser window.
    Useful for testing responsive designs (Mobile: 375x812, Desktop: 1920x1080).
    """
    manager = get_manager()
    return await manager.set_viewport_size(width, height)


@tool
async def scan_page_security() -> str:
    """
    Run a security audit on the current page content.

    Returns a report containing:
    - Insecure forms (HTTP targets).
    - Potential sensitive comments (TODOs, API keys).
    - Exposed secrets in the DOM or Storage.
    - Suspicious Console logs.
    """
    manager = get_manager()
    return await manager.analyze_page_security()


# --- Export all tools ---


def get_web_agent_tools() -> List:
    """Get all web agent tools for binding to LangChain."""
    return [
        open_browser,
        navigate_to_url,
        get_page_content,
        click_element,
        type_into_element,
        scroll_page,
        take_screenshot,
        execute_js,
        browser_go_back,
        browser_go_forward,
        close_browser,
        wait_for_page_element,
        download_file,
        download_all_links,
        hover_element,
        press_key,
        handle_next_dialog,
        get_browser_tabs,
        switch_browser_tab,
        get_element_details,
        wait_for_network_idle,
        reload_page,
        set_local_storage,
        get_local_storage,
        clear_cookies,
        select_dropdown_option,
        toggle_checkbox,
        highlight_page_element,
        save_page_as_pdf,
        upload_file_to_selector,
        drag_element_to_target,
        switch_to_iframe,
        set_browser_geolocation,
        set_browser_viewport,
        scan_page_security,
    ]


# --- Convenience function for direct usage ---


async def quick_browse(url: str, extract: bool = True) -> str:
    """
    Quick helper to browse a URL and optionally extract content.

    Usage:
        result = await quick_browse("https://example.com")
    """
    manager = get_manager()

    if not manager.is_initialized:
        await manager.initialize()

    nav_result = await manager.navigate(url)

    if extract:
        content = await manager.get_page_content()
        return f"{nav_result}\n\n{content}"

    return nav_result


@tool
async def browser_forensics_auditor() -> str:
    """
    Performs forensic-level extraction from the current browser session.
    Extracts history, installed extensions, and sensitive local storage keys.
    """
    global _browser_manager
    if not _browser_manager or not _browser_manager.is_initialized:
        return format_industrial_result(
            "browser_forensics_auditor", "Error", error="Browser not initialized"
        )

    try:
        page = _browser_manager.page

        # 1. Extract Extensions (Simulated via navigator.plugins/permissions)
        extensions = await page.evaluate("() => navigator.plugins.length")

        # 2. Extract LocalStorage Keys (High Value)
        storage_keys = await page.evaluate("() => Object.keys(localStorage)")
        sensitive_keys = [
            k
            for k in storage_keys
            if any(x in k.lower() for x in ["token", "session", "auth", "key"])
        ]

        # 3. Extract History (Simulated via interaction history)
        history_count = len(_browser_manager.interaction_history)

        return format_industrial_result(
            "browser_forensics_auditor",
            "Forensics Complete",
            confidence=0.9,
            impact="HIGH",
            raw_data={
                "extensions_count": extensions,
                "sensitive_storage_keys": sensitive_keys,
                "history_snapshot": history_count,
            },
            summary=f"Browser forensics finalized. Identified {len(sensitive_keys)} sensitive storage keys and audited {history_count} session events.",
        )
    except Exception as e:
        return format_industrial_result(
            "browser_forensics_auditor", "Error", error=str(e)
        )


@tool
async def sophisticated_session_cookie_extractor() -> str:
    """
    Performs high-fidelity extraction of session cookies for high-value targets.
    Industry-grade for bypassing session-based security controls and account takeovers.
    """
    global _browser_manager
    if not _browser_manager or not _browser_manager.is_initialized:
        return format_industrial_result(
            "sophisticated_session_cookie_extractor",
            "Error",
            error="Browser not initialized",
        )

    try:
        context = _browser_manager.context
        cookies = await context.cookies()

        # Filter for high-value session cookies

        session_cookies = [
            c
            for c in cookies
            if any(x in c["name"].lower() for x in ["sess", "auth", "token", "sid"])
        ]

        return format_industrial_result(
            "sophisticated_session_cookie_extractor",
            "Cookies Extracted",
            confidence=1.0,
            impact="CRITICAL",
            raw_data={
                "total_cookies": len(cookies),
                "session_cookies": session_cookies,
            },
            summary=f"Sophisticated cookie extraction complete. Captured {len(session_cookies)} high-value session tokens for current session.",
        )
    except Exception as e:
        return format_industrial_result(
            "sophisticated_session_cookie_extractor", "Error", error=str(e)
        )
