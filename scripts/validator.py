"""
Wazuh Rule Validator Agent
============================

Validates generated Wazuh XML rules against:
  - XML syntax correctness
  - Parent rule existence and validity (if_sid)
  - Decoder field compatibility
  - Platform/logsource consistency

Usage:
    from validator import ValidatorAgent
    validator = ValidatorAgent(chroma_db_instance)
    is_valid, reviews = validator.validate(xml_string, platform, decoder_name)

Logs:
    logs/validator.log
"""

import re
import xml.etree.ElementTree as ET
from langchain_core.documents import Document
from utils import build_chroma_filter

from logger import setup_logger

logger = setup_logger("validator", level="INFO")


class ValidatorAgent:
    """
    Validates Wazuh XML rules generated from Sigma rules.

    Checks:
        1. XML is well-formed
        2. if_sid points to a valid parent (exists, correct platform, is grouping rule)
        3. All <field name="..."> tags reference fields the decoder actually extracts
        4. Static fields (url, srcip, etc.) use dedicated tags, not <field name="...">

    Usage:
        validator = ValidatorAgent(db)
        is_valid, reviews = validator.validate(xml_rule, "web", "web-accesslog")
        if not is_valid:
            # Pass reviews back to LLM for regeneration
    """

    # Fields that have dedicated XML tags in Wazuh (must NOT use <field name="...">)
    STATIC_FIELDS = ["url", "srcip", "dstip", "user", "id", "protocol", "action", "status"]

    def __init__(self, db):
        """
        Args:
            db: ChromaDB instance with wazuh_knowledge_base collection
        """
        self.db = db
        self.reviews = []
        logger.info("ValidatorAgent initialized")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self, xml_string: str, expected_platform: str, expected_decoder: str) -> tuple[bool, list[str]]:
        """
        Run all validation checks on a generated Wazuh rule.

        Args:
            xml_string: The generated Wazuh XML rule
            expected_platform: Platform from classify_sigma_rule() ("web", "windows", etc.)
            expected_decoder: Decoder name from classify_sigma_rule()

        Returns:
            (is_valid, reviews)
            is_valid = True  -> rule passes all checks
            is_valid = False -> reviews contains error messages for LLM
        """
        self.reviews = []
        logger.info(f"Starting validation (platform={expected_platform}, decoder={expected_decoder})")
        logger.debug(f"XML to validate:\n{xml_string[:300]}...")

        # Check 1: XML syntax
        logger.info("[Check 1/3] Validating XML syntax...")
        valid, error = self._validate_xml_syntax(xml_string)
        if not valid:
            logger.error(f"XML syntax failed: {error}")
            self.reviews.append(error)
        else:
            logger.info("XML syntax: PASS")

        # Check 2: if_sid (only if XML was parseable)
        if valid:
            logger.info("[Check 2/3] Validating if_sid...")
            valid_sid, error = self._validate_if_sid(xml_string, expected_platform)
            if not valid_sid:
                logger.error(f"if_sid validation failed: {error}")
                self.reviews.append(error)
                suggested = self._find_valid_parent(expected_platform)
                if suggested:
                    logger.info(f"Suggested alternative parent: {suggested}")
                    self.reviews.append(f"Suggested valid parent: {suggested}")
            else:
                logger.info("if_sid: PASS")

        # Check 3: Decoder fields
        logger.info("[Check 3/3] Validating decoder fields...")
        valid_fields, error = self._validate_decoder_fields(xml_string, expected_decoder)
        if not valid_fields:
            logger.error(f"Decoder field validation failed: {error}")
            self.reviews.append(error)
        else:
            logger.info("Decoder fields: PASS")

        is_valid = len(self.reviews) == 0
        if is_valid:
            logger.info("VALIDATION PASSED - Rule is valid!")
        else:
            logger.warning(f"VALIDATION FAILED - {len(self.reviews)} error(s) found")
            for i, review in enumerate(self.reviews, 1):
                logger.warning(f"  Error {i}: {review[:100]}...")

        return is_valid, self.reviews

    # ------------------------------------------------------------------
    # Internal Checks
    # ------------------------------------------------------------------

    def _validate_xml_syntax(self, xml_string: str) -> tuple[bool, str | None]:
        """Check if XML is well-formed."""
        try:
            ET.fromstring(xml_string)
            return True, None
        except ET.ParseError as e:
            return False, f"XML syntax error: {e}"

    def _validate_if_sid(self, xml_string: str, expected_platform: str) -> tuple[bool, str | None]:
        """
        Validate the <if_sid> parent reference.

        Checks:
            - Parent exists in DB
            - Parent platform matches expected platform
            - Parent is a valid grouping rule (level <= 2 or has_children=True)
        """
        match = re.search(r'<if_sid>(\d+)</if_sid>', xml_string)
        if not match:
            logger.debug("No if_sid found - standalone rule, valid")
            return True, None

        parent_id = match.group(1)
        logger.debug(f"Found if_sid={parent_id}, looking up in DB...")
        parent = self._get_rule_by_id(parent_id)

        if not parent:
            logger.debug(f"Parent {parent_id} not found in DB")
            return False, f"Parent rule {parent_id} does not exist in the knowledge base"

        # Platform match
        parent_platform = parent.metadata.get("platform", "unknown")
        logger.debug(f"Parent {parent_id}: platform={parent_platform}, level={parent.metadata.get('rule_level')}, has_children={parent.metadata.get('has_children')}")

        if expected_platform != "unknown" and parent_platform != expected_platform:
            return False, (
                f"Parent {parent_id} handles {parent_platform} events, "
                f"but this Sigma rule is for {expected_platform}. "
                f"Choose a parent in the {expected_platform} category."
            )

        # Valid grouping rule check
        parent_level = int(parent.metadata.get("rule_level", 0) or 0)
        has_children = parent.metadata.get("has_children", False)

        # Level 0-2 = always grouping rules
        # Level 3+ = must have proven children to be a valid parent
        is_grouping = (parent_level <= 2) or has_children

        if not is_grouping:
            return False, (
                f"Parent {parent_id} is not a valid grouping rule "
                f"(level={parent_level}, has_children={has_children}). "
                f"Choose a parent with level <= 2 or existing children."
            )

        logger.debug(f"Parent {parent_id} is valid grouping rule")
        return True, None

    def _validate_decoder_fields(self, xml_string: str, decoder_name: str) -> tuple[bool, str | None]:
        """
        Validate that all <field name="..."> tags:
            - Do not use static fields (url, srcip, etc.)
            - Reference fields the decoder actually extracts
        """
        logger.debug(f"Looking up decoder: {decoder_name}")
        decoder = self._get_decoder_by_name(decoder_name)
        if not decoder:
            logger.debug(f"Decoder {decoder_name} not found")
            return False, f"Decoder '{decoder_name}' not found in the knowledge base"

        extracted_fields = decoder.metadata.get("extracted_fields") or []
        # Handle None values from ChromaDB
        if extracted_fields is None:
            extracted_fields = []
        logger.debug(f"Decoder {decoder_name} extracts: {extracted_fields}")

        field_matches = re.findall(r'<field name="([^"]+)"', xml_string)
        logger.debug(f"Found <field> tags: {field_matches}")

        if not field_matches:
            logger.debug("No <field> tags to validate")
            return True, None

        errors = []
        for field in field_matches:
            if field in self.STATIC_FIELDS:
                errors.append(
                    f"Static field '{field}' must use <{field}> tag, "
                    f"not <field name='{field}'>"
                )
            elif field not in extracted_fields and field != "full_log":
                errors.append(
                    f"Field '{field}' is not extracted by decoder '{decoder_name}'. "
                    f"Available fields: {extracted_fields}. "
                    f"Use <full_log> as fallback if needed."
                )

        if errors:
            return False, "; ".join(errors)

        return True, None

    # ------------------------------------------------------------------
    # DB Helpers
    # ------------------------------------------------------------------

    def _get_rule_by_id(self, rule_id: str) -> Document | None:
        """Lookup a rule by exact ID from ChromaDB."""
        logger.debug(f"DB query: rule_id={rule_id}")
        chroma_filter = build_chroma_filter({"type": "rule", "rule_id": rule_id})
        results = self.db.similarity_search("", k=1, filter=chroma_filter)
        return results[0] if results else None

    def _get_decoder_by_name(self, decoder_name: str) -> Document | None:
        """Lookup a decoder by exact name from ChromaDB."""
        logger.debug(f"DB query: decoder_name={decoder_name}")
        chroma_filter = build_chroma_filter({"type": "decoder", "decoder_name": decoder_name})
        results = self.db.similarity_search("", k=1, filter=chroma_filter)
        return results[0] if results else None

    def _find_valid_parent(self, platform: str) -> str | None:
        """Find a valid grouping rule for the given platform."""
        logger.debug(f"Searching for valid parent in platform={platform}")
        chroma_filter = build_chroma_filter({"type": "rule", "platform": platform, "has_children": True})
        results = self.db.similarity_search("", k=3, filter=chroma_filter)
        if results:
            parent_id = results[0].metadata.get("rule_id")
            logger.debug(f"Found candidate parent: {parent_id}")
            return parent_id
        logger.debug("No valid parent found")
        return None