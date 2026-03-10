"""
CyberIntel Platform — Website Fingerprinting Crawler

Uses Playwright headless browser to:
- Capture screenshots
- Hash HTML structure
- Detect login forms
- Fingerprint favicon
- Detect JS libraries
- Compute DOM structure signature
"""
import hashlib
import logging
import os
import re
from typing import Optional
from datetime import datetime

from app.core.config import settings
from app.core.network import network

logger = logging.getLogger("cyberintel.crawler")


class WebsiteCrawler:
    """
    Headless browser crawler for website fingerprinting.
    Detects cloned phishing pages by comparing structural signatures.
    """

    JS_LIBRARIES = [
        ("jquery", r"jquery[\.\-]?\d*"),
        ("bootstrap", r"bootstrap[\.\-]?\d*"),
        ("react", r"react[\.\-]?\d*"),
        ("vue", r"vue[\.\-]?\d*"),
        ("angular", r"angular[\.\-]?\d*"),
        ("lodash", r"lodash[\.\-]?\d*"),
        ("moment", r"moment[\.\-]?\d*"),
    ]

    async def crawl(self, url: str) -> dict:
        """
        Crawl a URL and produce a fingerprint profile.
        """
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        result = {
            "url": url,
            "crawled_at": datetime.utcnow().isoformat(),
            "title": None,
            "html_hash": None,
            "html_structure_hash": None,
            "favicon_hash": None,
            "screenshot_path": None,
            "has_login_form": False,
            "login_form_details": {},
            "js_libraries": [],
            "dom_signature": None,
            "meta_tags": {},
            "external_resources": [],
            "page_size_bytes": 0,
        }

        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as pw:
                browser_args = {
                    "headless": True,
                    "args": [
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                    ]
                }

                browser = await pw.chromium.launch(**browser_args)

                context_args = {
                    "user_agent": network.random_user_agent,
                    "viewport": {"width": 1920, "height": 1080},
                    "ignore_https_errors": True,
                }

                # Apply proxy from anonymization layer
                proxy_config = network.get_playwright_proxy()
                if proxy_config:
                    context_args["proxy"] = proxy_config

                context = await browser.new_context(**context_args)
                page = await context.new_page()

                try:
                    response = await page.goto(
                        url,
                        wait_until="networkidle",
                        timeout=settings.CRAWLER_TIMEOUT,
                    )

                    if response:
                        result["status_code"] = response.status
                        result["final_url"] = page.url

                    # Page title
                    result["title"] = await page.title()

                    # Full HTML content
                    html_content = await page.content()
                    result["page_size_bytes"] = len(html_content.encode())
                    result["html_hash"] = hashlib.sha256(
                        html_content.encode()
                    ).hexdigest()

                    # Structural hash (tags only, no content)
                    structure = self._extract_structure(html_content)
                    result["html_structure_hash"] = hashlib.sha256(
                        structure.encode()
                    ).hexdigest()

                    # DOM signature
                    result["dom_signature"] = await self._compute_dom_signature(page)

                    # Login form detection
                    login_info = await self._detect_login_form(page)
                    result["has_login_form"] = login_info["detected"]
                    result["login_form_details"] = login_info

                    # JS library detection
                    result["js_libraries"] = await self._detect_js_libraries(page, html_content)

                    # Meta tags
                    result["meta_tags"] = await self._extract_meta_tags(page)

                    # Favicon hash
                    result["favicon_hash"] = await self._hash_favicon(page, url)

                    # Screenshot
                    screenshot_path = await self._take_screenshot(page, url)
                    result["screenshot_path"] = screenshot_path

                    # External resources
                    result["external_resources"] = await self._extract_external_resources(page)

                    logger.info(
                        f"Crawled {url}: title='{result['title']}' "
                        f"login_form={result['has_login_form']} "
                        f"js_libs={len(result['js_libraries'])}"
                    )

                except Exception as e:
                    result["error"] = str(e)
                    logger.warning(f"Crawl error for {url}: {e}")

                finally:
                    await context.close()
                    await browser.close()

        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Playwright launch failed: {e}")

        return result

    def _extract_structure(self, html: str) -> str:
        """Extract tag-only skeleton from HTML for structural comparison."""
        tags = re.findall(r'</?[a-zA-Z][a-zA-Z0-9]*[^>]*/?>', html)
        # Keep only tag names
        tag_names = []
        for tag in tags:
            match = re.match(r'</?([a-zA-Z][a-zA-Z0-9]*)', tag)
            if match:
                tag_names.append(match.group(0))
        return "|".join(tag_names)

    async def _compute_dom_signature(self, page) -> str:
        """Compute a structural fingerprint of the DOM tree."""
        signature = await page.evaluate("""
            () => {
                function walk(node, depth) {
                    if (depth > 10) return '';
                    let sig = node.tagName || '';
                    const children = Array.from(node.children || []);
                    sig += '(' + children.length + ')';
                    for (const child of children.slice(0, 20)) {
                        sig += walk(child, depth + 1);
                    }
                    return sig;
                }
                return walk(document.documentElement, 0);
            }
        """)
        return hashlib.md5(signature.encode()).hexdigest()

    async def _detect_login_form(self, page) -> dict:
        """Detect presence of login/credential forms."""
        detection = await page.evaluate("""
            () => {
                const forms = document.querySelectorAll('form');
                const passwordFields = document.querySelectorAll(
                    'input[type="password"]'
                );
                const emailFields = document.querySelectorAll(
                    'input[type="email"], input[name*="email"], input[name*="user"], input[name*="login"]'
                );
                const submitBtns = document.querySelectorAll(
                    'button[type="submit"], input[type="submit"]'
                );

                const hasLogin = passwordFields.length > 0 && (
                    emailFields.length > 0 || forms.length > 0
                );

                return {
                    detected: hasLogin,
                    form_count: forms.length,
                    password_fields: passwordFields.length,
                    email_fields: emailFields.length,
                    submit_buttons: submitBtns.length,
                    form_actions: Array.from(forms).map(f => f.action).slice(0, 5),
                };
            }
        """)
        return detection

    async def _detect_js_libraries(self, page, html_content: str) -> list[str]:
        """Detect JavaScript libraries loaded on the page."""
        detected = []
        html_lower = html_content.lower()

        for lib_name, pattern in self.JS_LIBRARIES:
            if re.search(pattern, html_lower):
                detected.append(lib_name)

        # Check via page context
        browser_detected = await page.evaluate("""
            () => {
                const libs = [];
                if (window.jQuery) libs.push('jquery');
                if (window.React) libs.push('react');
                if (window.Vue) libs.push('vue');
                if (window.angular) libs.push('angular');
                if (window._) libs.push('lodash');
                return libs;
            }
        """)

        return list(set(detected + browser_detected))

    async def _extract_meta_tags(self, page) -> dict:
        """Extract meta tags from the page."""
        return await page.evaluate("""
            () => {
                const metas = {};
                document.querySelectorAll('meta').forEach(m => {
                    const name = m.getAttribute('name') || m.getAttribute('property') || '';
                    const content = m.getAttribute('content') || '';
                    if (name && content) metas[name] = content;
                });
                return metas;
            }
        """)

    async def _hash_favicon(self, page, url: str) -> Optional[str]:
        """Download and hash the favicon."""
        try:
            favicon_url = await page.evaluate("""
                () => {
                    const link = document.querySelector(
                        'link[rel*="icon"], link[rel="shortcut icon"]'
                    );
                    return link ? link.href : null;
                }
            """)

            if not favicon_url:
                # Try default location
                from urllib.parse import urlparse
                parsed = urlparse(url)
                favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"

            response = await network.get(favicon_url)
            if response.status_code == 200 and len(response.content) > 0:
                return hashlib.md5(response.content).hexdigest()

        except Exception as e:
            logger.debug(f"Favicon hash failed for {url}: {e}")

        return None

    async def _take_screenshot(self, page, url: str) -> Optional[str]:
        """Take a screenshot of the page."""
        try:
            os.makedirs(settings.SCREENSHOT_DIR, exist_ok=True)
            filename = hashlib.md5(url.encode()).hexdigest() + ".png"
            filepath = os.path.join(settings.SCREENSHOT_DIR, filename)
            await page.screenshot(path=filepath, full_page=False)
            logger.info(f"Screenshot saved: {filepath}")
            return filepath
        except Exception as e:
            logger.debug(f"Screenshot failed for {url}: {e}")
            return None

    async def _extract_external_resources(self, page) -> list[str]:
        """Extract external resource URLs (scripts, styles, images)."""
        return await page.evaluate("""
            () => {
                const resources = new Set();
                document.querySelectorAll('script[src]').forEach(
                    s => resources.add(s.src)
                );
                document.querySelectorAll('link[href]').forEach(
                    l => resources.add(l.href)
                );
                return Array.from(resources).slice(0, 50);
            }
        """)
