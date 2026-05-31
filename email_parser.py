"""
Full Email Parser + Feature Extractor (Production-Grade Upgrade)

Fixes:
- False positives on .edu.au / institutional emails
- Over-aggressive urgency detection
- ESP (Mailchimp, SES, SendGrid) false mismatch issues
- Missing institutional context detection
- Weak phishing intent separation
"""

import email
from email import policy
from email.parser import BytesParser
import re

# ================================
# TRUSTED ESP INFRASTRUCTURE
# ================================
KNOWN_ESP_DOMAINS = {
    "amazonses.com",
    "amazon.com",
    "mailchimp.com",
    "mandrillapp.com",
    "mcsv.net",
    "list-manage.com",
    "sendgrid.net",
    "sendgrid.com",
    "mailgun.org",
    "mailgun.com",
    "hubspot.com",
    "hs-analytics.net",
    "sidekickopen.com",
    "salesforce.com",
    "exacttarget.com",
    "pardot.com",
    "constantcontact.com",
    "r.constantcontact.com",
    "campaignmonitor.com",
    "cmail1.com",
    "cmail2.com",
    "klaviyo.com",
    "postmarkapp.com",
    "sparkpostmail.com",
    "sparkpost.com",
    "twilio.com",
    "googlemail.com",
    "google.com",
    "outlook.com",
    "microsoft.com",
    "zendesk.com",
    "freshdesk.com",
    "intercom.io",
}


# =========================================================
# FULL EMAIL PARSER
# =========================================================
class FullEmailParser:

    def __init__(self):

        self.institutional_keywords = [
            "unit coordinator",
            "lecture",
            "tutorial",
            "assignment",
            "exam",
            "attendance",
            "campus",
            "timetable",
            "class",
            "student",
            "semester",
            "course",
            "assessment",
            "submission",
            "deadline",
            "week",
        ]

        self.credential_keywords = [
            "password",
            "login",
            "verify account",
            "reset password",
            "confirm identity",
            "bank account",
            "credit card",
            "security check",
        ]

        self.urgent_words = [
            "urgent",
            "immediate",
            "action required",
            "verify now",
            "suspend",
            "limited time",
            "act now",
            "warning",
            "alert",
        ]

    # -----------------------------
    # DOMAIN NORMALIZATION
    # -----------------------------
    def _get_base_domain(self, value):
        if not value:
            return ""

        if "@" in value:
            value = value.split("@")[-1]

        value = value.strip("<>").lower()
        parts = value.split(".")

        if len(parts) >= 2:
            return ".".join(parts[-2:])

        return value

    def _is_esp_domain(self, domain):
        return self._get_base_domain(domain) in KNOWN_ESP_DOMAINS

    # -----------------------------
    # EMAIL PARSING
    # -----------------------------
    def parse_full_email(self, raw_email):

        try:
            if isinstance(raw_email, str):
                raw_bytes = raw_email.encode("utf-8", errors="surrogateescape")
                msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
            else:
                msg = BytesParser(policy=policy.default).parsebytes(raw_email)

            headers = {k: str(v) for k, v in msg.items()}

            body_plain = ""
            body_html = ""
            attachments = []

            # -------------------------
            # BODY EXTRACTION
            # -------------------------
            if msg.is_multipart():
                for part in msg.walk():

                    content_type = part.get_content_type()
                    disposition = part.get("Content-Disposition", "") or ""

                    if "attachment" in disposition.lower():
                        filename = part.get_filename()
                        payload = part.get_payload(decode=True) or b""

                        if filename:
                            attachments.append(
                                {
                                    "filename": filename,
                                    "size": len(payload),
                                    "type": content_type,
                                }
                            )

                    else:
                        payload = part.get_payload(decode=True)

                        if payload:
                            content = payload.decode("utf-8", errors="ignore")

                            if content_type == "text/plain":
                                body_plain += content
                            elif content_type == "text/html":
                                body_html += content

            else:
                payload = msg.get_payload(decode=True)

                if payload:
                    content = payload.decode("utf-8", errors="ignore")

                    if msg.get_content_type() == "text/html":
                        body_html = content
                    else:
                        body_plain = content

            body = f"{body_plain} {body_html}".strip()

            urls = self._extract_urls(body)

            # -------------------------
            # HEADER EXTRACTION
            # -------------------------
            from_addr = headers.get("From", "")
            reply_to = headers.get("Reply-To", "")
            return_path = headers.get("Return-Path", "")

            parsed = {
                "headers": headers,
                "subject": headers.get("Subject", ""),
                "from": from_addr,
                "reply_to": reply_to,
                "return_path": return_path,
                "authentication_results": headers.get("Authentication-Results", ""),
                "body_plain": body_plain,
                "body_html": body_html,
                "body_combined": body,
                "urls": urls,
                "attachments": attachments,
                "raw": raw_email,
            }

            return parsed

        except Exception:
            return self._fallback_parse(raw_email)

    # -----------------------------
    # URL EXTRACTION
    # -----------------------------
    def _extract_urls(self, text):
        pattern = r"(https?://[^\s]+|www\.[^\s]+)"
        return list(set(re.findall(pattern, text)))

    # -----------------------------
    # FALLBACK PARSER
    # -----------------------------
    def _fallback_parse(self, raw_email):

        text = (
            raw_email.decode("utf-8", errors="ignore")
            if isinstance(raw_email, bytes)
            else raw_email
        )

        headers = {}
        for line in text.split("\n")[:80]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        return {
            "headers": headers,
            "subject": headers.get("Subject", ""),
            "from": headers.get("From", ""),
            "reply_to": headers.get("Reply-To", ""),
            "return_path": headers.get("Return-Path", ""),
            "authentication_results": headers.get("Authentication-Results", ""),
            "body_plain": text,
            "body_html": "",
            "body_combined": text,
            "urls": self._extract_urls(text),
            "attachments": [],
            "raw": text,
        }


# =========================================================
# FEATURE EXTRACTOR (FIXED VERSION)
# =========================================================
# =========================================================
# ENHANCED FEATURE EXTRACTOR (Grammar & Writing Quality Focus)
# =========================================================
class EnhancedFeatureExtractor:

    def __init__(self):
        self.institutional_keywords = [
            "unit coordinator",
            "lecture",
            "tutorial",
            "assignment",
            "exam",
            "attendance",
            "campus",
            "timetable",
            "class",
            "student",
            "semester",
            "course",
            "assessment",
            "submission",
            "deadline",
            "week",
        ]
        self.credential_keywords = [
            "password",
            "login",
            "verify account",
            "reset password",
            "confirm identity",
            "bank account",
            "credit card",
        ]
        # Basic common English words for spelling error estimation (first 500 common words)
        # In production, load a proper word list; here a small sample for demonstration.
        self.common_words = {
            "the",
            "be",
            "to",
            "of",
            "and",
            "a",
            "in",
            "that",
            "have",
            "i",
            "it",
            "for",
            "not",
            "on",
            "with",
            "he",
            "as",
            "you",
            "do",
            "at",
            "this",
            "but",
            "his",
            "by",
            "from",
            "they",
            "we",
            "say",
            "her",
            "she",
            "or",
            "an",
            "will",
            "my",
            "one",
            "all",
            "would",
            "there",
            "their",
            "what",
            "so",
            "up",
            "out",
            "if",
            "about",
            "who",
            "get",
            "which",
            "go",
            "me",
            "when",
            "make",
            "can",
            "like",
            "time",
            "no",
            "just",
            "him",
            "know",
            "take",
            "people",
            "into",
            "year",
            "your",
            "good",
            "some",
            "could",
            "them",
            "see",
            "other",
            "than",
            "then",
            "now",
            "look",
            "only",
            "come",
            "its",
            "over",
            "think",
            "also",
            "back",
            "after",
            "use",
            "two",
            "how",
            "our",
            "work",
            "first",
            "well",
            "way",
            "even",
            "new",
            "want",
            "because",
            "any",
            "these",
            "give",
            "day",
            "most",
            "us",
        }

    def _get_base_domain(self, value):
        if not value:
            return ""
        if "@" in value:
            value = value.split("@")[-1]
        value = value.strip("<>").lower()
        parts = value.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return value

    # ========== GRAMMAR & WRITING QUALITY FEATURES ==========
    def _exclamation_count(self, text):
        return text.count("!")

    def _question_mark_count(self, text):
        return text.count("?")

    def _repeated_punctuation(self, text):
        # Count sequences like !!, ???, ..., --
        import re

        patterns = [r"!{2,}", r"\?{2,}", r"\.{3,}", r"-{2,}"]
        return sum(len(re.findall(p, text)) for p in patterns)

    def _caps_ratio(self, text):
        letters = [c for c in text if c.isalpha()]
        if not letters:
            return 0.0
        caps = sum(1 for c in letters if c.isupper())
        return caps / len(letters)

    def _longest_caps_run(self, text):
        import re

        runs = re.findall(r"[A-Z]+", text)
        return max((len(r) for r in runs), default=0)

    def _suspicious_typo_count(self, text):
        # Heuristic: repeated letters (e.g., "pwword", "helllo") or digit substitution
        import re

        repeated_letters = len(re.findall(r"([a-z])\1{2,}", text.lower()))
        digit_substitution = len(re.findall(r"\d+[a-z]|[a-z]\d+", text.lower()))
        return repeated_letters + digit_substitution

    def _unnatural_spacing(self, text):
        # Multiple spaces, tabs, or missing space after period/comma
        import re

        multi_spaces = len(re.findall(r" {2,}", text))
        missing_space_after_punct = len(re.findall(r"[.,!?][a-zA-Z0-9]", text))
        return multi_spaces + missing_space_after_punct

    def _word_repetition(self, text):
        # Consecutive duplicate words (e.g., "click click")
        words = text.split()
        if len(words) < 2:
            return 0
        duplicates = sum(
            1 for i in range(len(words) - 1) if words[i].lower() == words[i + 1].lower()
        )
        return duplicates

    def _spelling_error_estimate(self, text):
        # Very rough estimate: count of lowercase words (≥4 letters) not in common_words list
        # Ignores punctuation and numbers
        import re

        words = re.findall(r"\b[a-z]{4,}\b", text.lower())
        if not words:
            return 0
        uncommon = sum(1 for w in words if w not in self.common_words)
        return uncommon

    # ========== MAIN FEATURE EXTRACTION ==========
    def extract_features(self, parsed):
        subject = parsed.get("subject", "").lower()
        body = parsed.get("body_combined", "").lower()
        from_addr = parsed.get("from", "").lower()
        urls = parsed.get("urls", [])

        from_domain = self._get_base_domain(from_addr)

        # Context features
        institutional_score = sum(
            1 for w in self.institutional_keywords if w in subject or w in body
        )
        credential_intent = int(any(w in body for w in self.credential_keywords))
        is_edu = int(".edu" in from_domain or ".edu.au" in from_domain)
        is_trusted_org = int(".gov" in from_domain or ".ac." in from_domain)
        institutional_override = int(
            institutional_score >= 2 and credential_intent == 0
        )

        # URL features
        url_text = " ".join(urls).lower()
        suspicious_url_score = sum(
            1 for k in ["login", "verify", "secure", "account"] if k in url_text
        )

        # Grammar & writing quality features
        exclamation_count = self._exclamation_count(body)
        question_mark_count = self._question_mark_count(body)
        repeated_punct = self._repeated_punctuation(body)
        caps_ratio = self._caps_ratio(body)
        longest_caps_run = self._longest_caps_run(body)
        typo_count = self._suspicious_typo_count(body)
        spacing_issues = self._unnatural_spacing(body)
        word_reps = self._word_repetition(body)
        spelling_estimate = self._spelling_error_estimate(body)

        features = {
            # Length features (keep but you can ignore later)
            "subject_length": len(subject),
            "body_length": len(body),
            # Core structure
            "num_urls": len(urls),
            "num_attachments": len(parsed.get("attachments", [])),
            # Context
            "institutional_score": institutional_score,
            "institutional_override": institutional_override,
            "credential_intent": credential_intent,
            # Domain trust
            "is_edu_domain": is_edu,
            "is_trusted_org": is_trusted_org,
            # URL risk
            "suspicious_url_score": suspicious_url_score,
            # Grammar / writing quality (NEW)
            "exclamation_count": exclamation_count,
            "question_mark_count": question_mark_count,
            "repeated_punctuation": repeated_punct,
            "caps_ratio": caps_ratio,
            "longest_caps_run": longest_caps_run,
            "typo_count": typo_count,
            "spacing_issues": spacing_issues,
            "word_repetition": word_reps,
            "spelling_error_estimate": spelling_estimate,
        }

        return features
