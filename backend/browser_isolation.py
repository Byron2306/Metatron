"""
Browser Isolation Service - Secure remote browsing
"""
import uuid
import hashlib
import base64
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from urllib.parse import urlparse, urlencode
import logging
import re

logger = logging.getLogger(__name__)

class IsolationMode(str, Enum):
    FULL = "full"           # Full remote rendering
    CONTENT_DISARM = "cdr"  # Content Disarm & Reconstruction
    READ_ONLY = "read_only" # Read-only mode, no interactions
    PIXEL_PUSH = "pixel_push"  # Stream as pixels only

class ThreatLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MALICIOUS = "malicious"

@dataclass
class IsolatedSession:
    session_id: str
    user_id: str
    original_url: str
    sanitized_url: str
    isolation_mode: IsolationMode
    started_at: str
    ended_at: Optional[str] = None
    threat_level: ThreatLevel = ThreatLevel.LOW
    blocked_elements: List[str] = field(default_factory=list)
    downloads_blocked: int = 0
    scripts_blocked: int = 0
    is_active: bool = True

@dataclass
class URLAnalysis:
    url: str
    domain: str
    threat_level: ThreatLevel
    reasons: List[str]
    category: str
    is_blocked: bool
    safe_url: Optional[str] = None

class BrowserIsolationService:
    def __init__(self):
        self.sessions: Dict[str, IsolatedSession] = {}
        self.url_cache: Dict[str, URLAnalysis] = {}
        self.blocked_domains: set = set()
        self.suspicious_patterns: List[str] = []
        self._init_threat_intelligence()
    
    def _init_threat_intelligence(self):
        """Initialize threat intelligence data"""
        # Known malicious domains (sample)
        self.blocked_domains = {
            "malware.com", "phishing-site.net", "evil.org",
            "cryptominer.io", "ransomware.xyz", "botnet.cc"
        }
        
        # Suspicious URL patterns
        self.suspicious_patterns = [
            r".*\.exe$",
            r".*\.dll$",
            r".*\.bat$",
            r".*\.ps1$",
            r".*\.vbs$",
            r".*download.*malware.*",
            r".*free.*crack.*",
            r".*keygen.*",
            r".*warez.*",
            r".*torrent.*",
            r".*\.tk$",
            r".*\.ml$",
            r".*\.ga$",
            r".*bit\.ly/.*",
            r".*tinyurl\.com/.*",
        ]
        
        # High-risk TLDs
        self.high_risk_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club"}
        
        # Categories
        self.category_keywords = {
            "social_media": ["facebook", "twitter", "instagram", "linkedin", "tiktok"],
            "email": ["gmail", "outlook", "yahoo", "mail"],
            "banking": ["bank", "paypal", "venmo", "chase", "wellsfargo"],
            "shopping": ["amazon", "ebay", "walmart", "shop"],
            "news": ["cnn", "bbc", "reuters", "news"],
            "entertainment": ["youtube", "netflix", "spotify", "twitch"],
            "productivity": ["google", "microsoft", "slack", "zoom"],
            "developer": ["github", "gitlab", "stackoverflow", "npm"]
        }
    
    def analyze_url(self, url: str) -> URLAnalysis:
        """Analyze a URL for threats"""
        # Check cache
        if url in self.url_cache:
            return self.url_cache[url]
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            full_url = url.lower()
        except Exception:
            return URLAnalysis(
                url=url,
                domain="invalid",
                threat_level=ThreatLevel.MALICIOUS,
                reasons=["Invalid URL format"],
                category="unknown",
                is_blocked=True
            )
        
        reasons = []
        threat_level = ThreatLevel.SAFE
        is_blocked = False
        
        # Check blocked domains
        if domain in self.blocked_domains or any(domain.endswith(f".{d}") for d in self.blocked_domains):
            reasons.append("Known malicious domain")
            threat_level = ThreatLevel.MALICIOUS
            is_blocked = True
        
        # Check suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.match(pattern, full_url):
                reasons.append(f"Matches suspicious pattern: {pattern}")
                if threat_level.value < ThreatLevel.HIGH.value:
                    threat_level = ThreatLevel.HIGH
        
        # Check high-risk TLDs
        for tld in self.high_risk_tlds:
            if domain.endswith(tld):
                reasons.append(f"High-risk TLD: {tld}")
                if threat_level == ThreatLevel.SAFE:
                    threat_level = ThreatLevel.MEDIUM
        
        # Check for IP-based URLs (often phishing)
        if re.match(r"^\d+\.\d+\.\d+\.\d+", domain):
            reasons.append("IP-based URL (potential phishing)")
            if threat_level.value < ThreatLevel.MEDIUM.value:
                threat_level = ThreatLevel.MEDIUM
        
        # Check for URL shorteners
        url_shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]
        if any(s in domain for s in url_shorteners):
            reasons.append("URL shortener detected")
            if threat_level == ThreatLevel.SAFE:
                threat_level = ThreatLevel.LOW
        
        # Check for suspicious query params
        suspicious_params = ["download", "exe", "install", "crack", "keygen"]
        if any(p in parsed.query.lower() for p in suspicious_params):
            reasons.append("Suspicious query parameters")
            if threat_level.value < ThreatLevel.MEDIUM.value:
                threat_level = ThreatLevel.MEDIUM
        
        # Determine category
        category = "unknown"
        for cat, keywords in self.category_keywords.items():
            if any(kw in domain for kw in keywords):
                category = cat
                break
        
        # Generate safe URL (proxied)
        safe_url = None
        if not is_blocked:
            safe_url = self._generate_safe_url(url)
        
        analysis = URLAnalysis(
            url=url,
            domain=domain,
            threat_level=threat_level,
            reasons=reasons if reasons else ["No threats detected"],
            category=category,
            is_blocked=is_blocked,
            safe_url=safe_url
        )
        
        # Cache result
        self.url_cache[url] = analysis
        
        return analysis
    
    def _generate_safe_url(self, original_url: str) -> str:
        """Generate a safe/proxied URL"""
        # In production, this would route through a secure proxy
        url_hash = hashlib.sha256(original_url.encode()).hexdigest()[:16]
        encoded_url = base64.urlsafe_b64encode(original_url.encode()).decode()
        return f"/api/browser-isolation/proxy/{url_hash}?url={encoded_url}"
    
    def create_session(
        self,
        user_id: str,
        url: str,
        isolation_mode: str = "full"
    ) -> Dict:
        """Create a new isolated browsing session"""
        # Analyze the URL first
        analysis = self.analyze_url(url)
        
        if analysis.is_blocked:
            return {
                "success": False,
                "error": "URL is blocked",
                "threat_level": analysis.threat_level.value,
                "reasons": analysis.reasons
            }
        
        session_id = f"iso_{uuid.uuid4().hex[:12]}"
        
        session = IsolatedSession(
            session_id=session_id,
            user_id=user_id,
            original_url=url,
            sanitized_url=analysis.safe_url or url,
            isolation_mode=IsolationMode(isolation_mode),
            started_at=datetime.now(timezone.utc).isoformat(),
            threat_level=analysis.threat_level
        )
        
        self.sessions[session_id] = session
        
        logger.info(f"Created isolated session {session_id} for user {user_id}")
        
        return {
            "success": True,
            "session_id": session_id,
            "safe_url": session.sanitized_url,
            "isolation_mode": isolation_mode,
            "threat_level": analysis.threat_level.value,
            "category": analysis.category
        }
    
    def end_session(self, session_id: str) -> bool:
        """End an isolated browsing session"""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        session.is_active = False
        session.ended_at = datetime.now(timezone.utc).isoformat()
        
        logger.info(f"Ended session {session_id}")
        return True
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session details"""
        session = self.sessions.get(session_id)
        if session:
            result = asdict(session)
            result["isolation_mode"] = session.isolation_mode.value
            result["threat_level"] = session.threat_level.value
            return result
        return None
    
    def get_active_sessions(self, user_id: Optional[str] = None) -> List[Dict]:
        """Get all active sessions"""
        sessions = [s for s in self.sessions.values() if s.is_active]
        if user_id:
            sessions = [s for s in sessions if s.user_id == user_id]
        
        return [
            {
                **asdict(s),
                "isolation_mode": s.isolation_mode.value,
                "threat_level": s.threat_level.value
            }
            for s in sessions
        ]
    
    def sanitize_html(self, html_content: str) -> Dict:
        """Sanitize HTML content (Content Disarm & Reconstruction)"""
        blocked_elements = []
        scripts_blocked = 0
        
        # Remove script tags
        script_pattern = r"<script[^>]*>.*?</script>"
        scripts = re.findall(script_pattern, html_content, re.DOTALL | re.IGNORECASE)
        scripts_blocked = len(scripts)
        html_content = re.sub(script_pattern, "<!-- script removed -->", html_content, flags=re.DOTALL | re.IGNORECASE)
        if scripts_blocked > 0:
            blocked_elements.append(f"{scripts_blocked} script tags")
        
        # Remove event handlers
        event_handlers = ["onclick", "onload", "onerror", "onmouseover", "onfocus", "onblur"]
        for handler in event_handlers:
            pattern = rf'{handler}\s*=\s*["\'][^"\']*["\']'
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                blocked_elements.append(f"{len(matches)} {handler} handlers")
            html_content = re.sub(pattern, "", html_content, flags=re.IGNORECASE)
        
        # Remove javascript: URLs
        js_url_pattern = r'href\s*=\s*["\']javascript:[^"\']*["\']'
        js_urls = re.findall(js_url_pattern, html_content, re.IGNORECASE)
        if js_urls:
            blocked_elements.append(f"{len(js_urls)} javascript: URLs")
        html_content = re.sub(js_url_pattern, 'href="#"', html_content, flags=re.IGNORECASE)
        
        # Remove iframes from untrusted sources
        iframe_pattern = r"<iframe[^>]*>.*?</iframe>"
        iframes = re.findall(iframe_pattern, html_content, re.DOTALL | re.IGNORECASE)
        if iframes:
            blocked_elements.append(f"{len(iframes)} iframes")
        html_content = re.sub(iframe_pattern, "<!-- iframe removed -->", html_content, flags=re.DOTALL | re.IGNORECASE)
        
        # Remove object/embed tags
        for tag in ["object", "embed", "applet"]:
            pattern = rf"<{tag}[^>]*>.*?</{tag}>"
            matches = re.findall(pattern, html_content, re.DOTALL | re.IGNORECASE)
            if matches:
                blocked_elements.append(f"{len(matches)} {tag} tags")
            html_content = re.sub(pattern, f"<!-- {tag} removed -->", html_content, flags=re.DOTALL | re.IGNORECASE)
        
        # Remove form actions (prevent credential theft)
        form_pattern = r'action\s*=\s*["\'][^"\']*["\']'
        forms = re.findall(form_pattern, html_content, re.IGNORECASE)
        if forms:
            blocked_elements.append(f"{len(forms)} form actions")
        html_content = re.sub(form_pattern, 'action="#"', html_content, flags=re.IGNORECASE)
        
        return {
            "sanitized_html": html_content,
            "blocked_elements": blocked_elements,
            "scripts_blocked": scripts_blocked,
            "is_safe": len(blocked_elements) == 0
        }
    
    def add_blocked_domain(self, domain: str) -> bool:
        """Add a domain to the blocklist"""
        domain = domain.lower().strip()
        if domain:
            self.blocked_domains.add(domain)
            # Clear cache for this domain
            self.url_cache = {k: v for k, v in self.url_cache.items() if domain not in k}
            return True
        return False
    
    def remove_blocked_domain(self, domain: str) -> bool:
        """Remove a domain from the blocklist"""
        domain = domain.lower().strip()
        if domain in self.blocked_domains:
            self.blocked_domains.discard(domain)
            return True
        return False
    
    def get_blocked_domains(self) -> List[str]:
        """Get all blocked domains"""
        return sorted(list(self.blocked_domains))
    
    def get_stats(self) -> Dict:
        """Get browser isolation statistics"""
        total_sessions = len(self.sessions)
        active_sessions = sum(1 for s in self.sessions.values() if s.is_active)
        
        # Count by threat level
        by_threat = {}
        for session in self.sessions.values():
            level = session.threat_level.value
            by_threat[level] = by_threat.get(level, 0) + 1
        
        # Count by mode
        by_mode = {}
        for session in self.sessions.values():
            mode = session.isolation_mode.value
            by_mode[mode] = by_mode.get(mode, 0) + 1
        
        total_blocked = sum(s.scripts_blocked + s.downloads_blocked for s in self.sessions.values())
        
        return {
            "total_sessions": total_sessions,
            "active_sessions": active_sessions,
            "blocked_domains": len(self.blocked_domains),
            "cached_analyses": len(self.url_cache),
            "by_threat_level": by_threat,
            "by_isolation_mode": by_mode,
            "total_threats_blocked": total_blocked,
            "available_modes": [m.value for m in IsolationMode]
        }


# Global instance
browser_isolation_service = BrowserIsolationService()
