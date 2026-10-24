"""
code/intent_classifier.py - Classifies request_text to determine if deletion was requested.
If not a deletion request (e.g. data access/export, invoice inquiry, password reset, profile update),
it returns False, indicating deletion_status = 'NOT_APPLICABLE'.
"""

import re
from typing import Tuple

# Positive deletion indicators across languages supported in the challenge
DELETION_PATTERNS = [
    # English
    r'\b(?:delet(?:e|ed|ion|ing|ions)?)\b',
    r'\b(?:eras(?:e|ed|ure|ing)?)\b',
    r'\b(?:clos(?:e|ed|ing)?\s+(?:(?:my|the|this|an)\s+)?account)\b',
    r'\b(?:remov(?:e|ed|al|ing|es)?)\b',
    r'\b(?:profile\s+is\s+gone|account\s+is\s+gone)\b',

    r'\b(?:purget?|forget|forgotten|de-identif(?:y|ication))\b',
    r'\b(?:gdpr\s+art(?:icle)?\.?\s*17|right\s+to\s+be\s+forgotten|right\s+to\s+erasure)\b',
    r'\b(?:clean(?:ed|ing)?\s+(?:my\s+)?personal\s+details)\b',
    # Spanish
    r'\b(?:elimin(?:ar|aci[oó]n|e|ado|ada|aron))\b',
    r'\b(?:borr(?:ar|ado|ada)?|suprim(?:ir|ido|ida)?|cancel(?:ar|aci[oó]n))\b',
    # Portuguese
    r'\b(?:exclus[aã]o|excluir|elimin(?:ar|a[cç][aã]o)|apag(?:ar|ado|ada))\b',
    # French
    r'\b(?:suppress(?:ion)?|supprim(?:er|é|ée|és)?|effac(?:er|ement|é)?)\b',
    # German
    r'\b(?:l[oö]sch(?:en|ung)?|schlie[ßs](?:en)?)\b',
    # Italian
    r'\b(?:cancell(?:are|azione)?|rimoz(?:ione)?)\b',
    # Japanese
    r'(?:削除|消去|解約)',
    # Korean
    r'(?:삭제|영구\s*삭제|탈퇴)',
]


# Explicit retention / non-deletion signals
NEGATIVE_INTENT_PATTERNS = [
    r'\b(?:leave\s+(?:the|my)\s+account\s+active)\b',
    r'\b(?:keep\s+(?:the|my)\s+account\s+(?:as\s+it\s+is|active|open))\b',
    r'\b(?:leave\s+(?:the|my)\s+(?:profile|purchase\s+history|account)\s+in\s+place)\b',
    r'\b(?:continue\s+using\s+the\s+service)\b',
    r'\b(?:do\s+not\s+delete|don\'t\s+delete|never\s+delete)\b',
    r'\b(?:keep\s+my\s+profile\s+active)\b',
]

# Standalone non-deletion request types (when NOT accompanied by a deletion request)
NON_DELETION_STANDALONE = [
    r'\b(?:invoices?\s+for\s+my\s+records|copy\s+of\s+(?:last\s+year\'s\s+)?invoices?|billing\s+receipts?)\b',
    r'\b(?:download\s+(?:my\s+)?account\s+information\s+in\s+a\s+portable\s+format|data\s+portability|gdpr\s+art(?:icle)?\.?\s*(?:15|20))\b',
    r'\b(?:(?:replace|update|change)\s+(?:the\s+)?(?:mobile\s+number|phone\s+number|email\s+address|profile\s+details)\b.*?\bleave\b)',
]


def classify_intent(request_text: str) -> Tuple[bool, str]:
    """
    Classify whether request_text authorizes deletion.
    
    Returns:
        (is_deletion_request, reason)
        If is_deletion_request is False, caller should set deletion_status = 'NOT_APPLICABLE' and steps_json = [].
    """
    if not request_text or not isinstance(request_text, str):
        return False, "EMPTY_TEXT"

    text = request_text.strip()

    # 1. Check for explicit negative intent ("leave account active", "keep account as it is")
    for pat in NEGATIVE_INTENT_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return False, f"NEGATIVE_INTENT: matched '{pat}'"

    # 2. Check for standalone non-deletion requests
    for pat in NON_DELETION_STANDALONE:
        if re.search(pat, text, re.IGNORECASE):
            return False, f"STANDALONE_NON_DELETION: matched '{pat}'"

    # 3. Check for positive deletion patterns across all supported languages
    for pat in DELETION_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return True, f"DELETION_AUTHORIZED: matched '{pat}'"

    # Default fallback: if no deletion request pattern detected
    return False, "NO_DELETION_KEYWORDS_FOUND"


def is_deletion_request(request_text: str) -> bool:
    """Convenience boolean helper."""
    authorized, _ = classify_intent(request_text)
    return authorized


if __name__ == "__main__":
    import sys
    if sys.stdout.encoding.lower() != "utf-8":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    # Quick self-test
    test_cases = [
        ("Please delete my account and personal data.", True),
        ("The mobile number on my profile is out of date. Please replace it with the new one and leave the account active.", False),
        ("I'd like to download my account information in a portable format. Please keep the account as it is.", False),
        ("I need a copy of last year's invoices for my records. Please leave my profile and purchase history in place.", False),
        ("Please change the email address used for this account. I want to continue using the service.", False),
        ("このメールアドレスに関連するアカウントの完全な削除を依頼します。", True),
        ("Je demande la suppression définitive du compte associé à cette adresse e-mail.", True),
        ("Solicito la eliminación permanente de la cuenta.", True),
    ]
    for text, expected in test_cases:
        res, reason = classify_intent(text)
        print(f"Text: {text[:50]}... -> {res} (Expected: {expected}) [{reason}]")
        assert res == expected, f"Failed on: {text}"
    print("All quick test cases passed!")

