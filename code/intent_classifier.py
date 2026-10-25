"""code/intent_classifier.py - Classifies request_text to determine if deletion was authorized.

If not a deletion request (e.g. data access/export, invoice inquiry, password reset,
marketing opt-out, profile update/rectification, negative assertions),
returns False, indicating deletion_status = 'NOT_APPLICABLE'.
"""

from __future__ import annotations

import re
from typing import Tuple

# Explicit negative assertions and non-deletion request patterns
NEGATIVE_INTENT_PATTERNS = [
    # 1. Explicit negative assertion against deletion/closure/erasure/removal
    r'\b(?:do\s+not\s+(?:delete|close|erase|remove)|don\'t\s+(?:delete|close|erase|remove)|never\s+(?:delete|close|erase|remove))\b',
    r'\b(?:not\s+(?:asking\s+for|requesting)\s+(?:deletion|erasure|removal))\b',
    r'\b(?:not\s+a\s+request\s+to\s+(?:delete|erase|close|remove))\b',
    r'\b(?:without\s+(?:deleting|removing|erasing|closing))\b',
    
    # 2. Explicit retention requests
    r'\b(?:leave\s+(?:the|my)\s+account\s+active)\b',
    r'\b(?:keep\s+(?:the|my)\s+account(?:\s+as\s+it\s+is|\s+active|\s+open)?)\b',
    r'\b(?:leave\s+(?:the|my)\s+(?:profile|purchase\s+history|account)\s+in\s+place)\b',
    r'\b(?:continue\s+using\s+the\s+service)\b',
    r'\b(?:keep\s+my\s+profile\s+active)\b',
    r'\b(?:i\s+still\s+use\s+it,\s*so\s*please\s*don\'t\s*delete)\b',
    
    # 3. Marketing / newsletter opt-out only
    r'\b(?:remove\s+me\s+from\s+marketing\s+lists\s+only)\b',
    r'\b(?:marketing\s+lists?\s+only|promotional\s+emails?\s+only)\b',
    r'\b(?:stop\s+the\s+promotional\s+emails)\b',
    r'\b(?:unsubscribe|opt[- ]?out)\b',
    
    # 4. Rectification / correction / update
    r'\b(?:misspelled\s+on\s+the\s+account)\b',
    r'\b(?:(?:replace|update|change)\s+(?:the\s+)?(?:mobile\s+number|phone\s+number|email\s+address|profile\s+details)\b.*?\bleave\b)',
    r'\b(?:change\s+the\s+email\s+address\s+used\s+for\s+this\s+account)\b',
    r'\b(?:update\s+(?:my\s+)?(?:phone|mobile|phone\s+number|mobile\s+number|email|email\s+address|profile|address))\b',
    r'\b(?:correct\s+it\s+without\s+removing)\b',
    
    # 5. Account access / login / password reset
    r'\b(?:resetting\s+the\s+login|reset\s+(?:my\s+)?password|can\'t\s+access\s+my\s+profile)\b',
    
    # 6. Invoices / billing receipts / order cancellation
    r'\b(?:invoices?\s+for\s+my\s+records|copy\s+of\s+(?:last\s+year\'s\s+)?invoices?|billing\s+receipts?)\b',
    r'\b(?:cancel\s+(?:my\s+)?(?:invoice|order|subscription|bill|payment))\b',
    
    # 7. Data portability / access / export copy
    r'\b(?:download\s+(?:my\s+)?account\s+information\s+in\s+a\s+portable\s+format|data\s+portability|gdpr\s+art(?:icle)?\.?\s*(?:15|20))\b',
    r'\b(?:tell\s+me\s+what\s+personal\s+information\s+you\s+hold|send\s+me\s+a\s+copy\s+of\s+the\s+information\s+held)\b',
]

# Explicit action verb + explicit account/data object binding across supported languages
DELETION_VERB_OBJECT_PATTERNS = [
    # English: deletion verb + target object
    r'\b(?:delet(?:e|ed|ion|ing)?|eras(?:e|ed|ure|ing)?|purget?|wipe|wiped)\b.*?\b(?:account|profile|personal\s+data|personal\s+information|details|records|export\s+file)\b',
    r'\b(?:account|profile|personal\s+data|personal\s+information|details|records|search\s+result|export\s+file)\b.*?\b(?:deleted|erased|purged|wiped|removed)\b',
    r'\b(?:account|profile)\b.*?\b(?:deleting|erasing|closing)\s+it\b',
    r'\b(?:clos(?:e|ed|ing)?)\s+(?:(?:all|any|the|my|this|an)\s+)*(?:account|profile)\b',
    r'\b(?:remov(?:e|ed|al|ing)?)\s+(?:(?:all|any|the|my|this|that)\s+)*(?:account|profile|personal\s+data|personal\s+information|personal\s+details|details|records|search\s+result|name\s+and\s+contact\s+details)\b',
    r'\b(?:profile|account)(?:\s+page)?\s+is\s+gone\b',
    r'\b(?:permanent\s+account[- ]deletion|account[- ]deletion\s+request|personal[- ]data\s+deletion|deletion\s+process\s+for\s+the\s+account)\b',
    r'\b(?:right\s+to\s+be\s+forgotten|right\s+to\s+erasure|gdpr\s+art(?:icle)?\.?\s*17)\b',
    r'\b(?:clean\s+(?:my\s+)?personal\s+details)\b',
    r'\b(?:audit\s+the\s+deletion|finish\s+the\s+deletion)\b',
    
    # Spanish
    r'(?:eliminaci[oó]n|eliminar|borrar|suprimir)\b.*?\b(?:cuenta|datos|perfil|informaci[oó]n)',
    r'(?:cuenta|datos|perfil)\b.*?\b(?:eliminad[ao]s?|borrad[ao]s?|suprimid[ao]s?)',
    
    # Portuguese
    r'(?:exclus[aã]o|excluir|eliminar|apagar)\b.*?\b(?:conta|datos|dados|perfil|informa[cç][oõ]es)',
    r'(?:conta|datos|dados|perfil)\b.*?\b(?:exclu[ií]d[ao]s?|eliminad[ao]s?|apagad[ao]s?)',
    
    # French
    r'(?:suppression|supprimer|effacer)\b.*?\b(?:compte|donn[ée]es|profil|informations)',
    r'(?:compte|donn[ée]es|profil)\b.*?\b(?:supprim[ée]e?s?|effac[ée]e?s?)',
    
    # German
    r'(?:l[oö]sch(?:en|ung)|schlie[ßs]en)\b.*?\b(?:konto|daten|profil|account)',
    r'(?:konto|daten|profil|account)\b.*?\b(?:gel[oö]scht|geschlossen)',
    
    # Italian
    r'(?:cancell(?:are|azione)|rimoz(?:ione)|eliminare)\b.*?\b(?:account|profilo|dati)',
    r'(?:account|profilo|dati)\b.*?\b(?:cancellat[oi]|rimoss[oi]|eliminat[oi])',
    
    # Japanese
    r'(?:アカウント|個人情報|データ|登録)(?:の|を)?(?:完全な)?(?:削除|消去|解約)',
    
    # Korean
    r'(?:계정|개인정보|데이터)(?:의|을)?\s*(?:영구\s*)?(?:삭제|탈퇴)',
]


def classify_intent(request_text: str) -> Tuple[bool, str]:
    """Classify whether request_text authorizes deletion.

    Returns:
        (is_deletion_request, reason)
        If is_deletion_request is False, caller should set deletion_status = 'NOT_APPLICABLE' and steps_json = [].
    """
    if not request_text or not isinstance(request_text, str):
        return False, "EMPTY_TEXT"

    text = request_text.strip()

    # 1. Negative intent & Non-deletion guards (checked first)
    for pat in NEGATIVE_INTENT_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return False, f"NEGATIVE_INTENT: matched '{pat}'"

    # 2. Positive deletion patterns with explicit object binding
    for pat in DELETION_VERB_OBJECT_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return True, f"DELETION_AUTHORIZED: matched '{pat}'"

    return False, "NO_VALID_DELETION_OBJECT_PAIR"


def is_deletion_request(request_text: str) -> bool:
    """Convenience boolean helper."""
    authorized, _ = classify_intent(request_text)
    return authorized
