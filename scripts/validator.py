"""
Wazuh Rule Validator Agent
Validates generated Wazuh XML rules against XML syntax, parent rules, decoder fields.
"""

import re
import xml.etree.ElementTree as ET
from langchain_core.documents import Document
from utils import build_chroma_filter
from logger import setup_logger

logger = setup_logger("validator", level="INFO")


class ValidatorAgent:
    STATIC_FIELDS = ["url", "srcip", "dstip", "user", "id", "protocol", "action", "status"]

    def __init__(self, db):
        self.db = db
        self.reviews = []
        logger.info("ValidatorAgent initialized")

    def validate(self, xml_string: str, expected_platform: str, expected_decoder: str) -> tuple[bool, list[str]]:
        self.reviews = []
        logger.info(f"Starting validation (platform={expected_platform}, decoder={expected_decoder})")

        # Check 1: XML syntax
        valid, error = self._validate_xml_syntax(xml_string)
        if not valid:
            self.reviews.append(error)
        else:
            logger.info("XML syntax: PASS")

        # Check 2: if_sid
        if valid:
            valid_sid, error = self._validate_if_sid(xml_string, expected_platform)
            if not valid_sid:
                self.reviews.append(error)
                suggested = self._find_valid_parent(expected_platform)
                if suggested:
                    self.reviews.append(f"Suggested valid parent: {suggested}")
            else:
                logger.info("if_sid: PASS")

        # Check 3: Decoder fields
        valid_fields, error = self._validate_decoder_fields(xml_string, expected_decoder)
        if not valid_fields:
            self.reviews.append(error)
        else:
            logger.info("Decoder fields: PASS")

        is_valid = len(self.reviews) == 0
        return is_valid, self.reviews

    def _validate_xml_syntax(self, xml_string: str) -> tuple[bool, str | None]:
        try:
            ET.fromstring(xml_string)
            return True, None
        except ET.ParseError as e:
            return False, f"XML syntax error: {e}"

    def _validate_if_sid(self, xml_string: str, expected_platform: str) -> tuple[bool, str | None]:
        match = re.search(r'<if_sid>(\d+)</if_sid>', xml_string)
        if not match:
            return True, None

        parent_id = match.group(1)
        parent = self._get_rule_by_id(parent_id)
        if not parent:
            return False, f"Parent rule {parent_id} does not exist in the knowledge base"

        parent_platform = parent.metadata.get("platform", "unknown")
        if expected_platform != "unknown" and parent_platform != expected_platform:
            return False, f"Parent {parent_id} handles {parent_platform} events, but this rule is for {expected_platform}"

        parent_level = int(parent.metadata.get("rule_level", 0) or 0)
        has_children = parent.metadata.get("has_children", False)
        is_grouping = (parent_level <= 2) or has_children

        if not is_grouping:
            return False, f"Parent {parent_id} is not a valid grouping rule (level={parent_level})"

        return True, None

    def _validate_decoder_fields(self, xml_string: str, decoder_name: str) -> tuple[bool, str | None]:
        decoder = self._get_decoder_by_name(decoder_name)
        if not decoder:
            return False, f"Decoder '{decoder_name}' not found in the knowledge base"

        extracted_fields = decoder.metadata.get("extracted_fields") or []
        if extracted_fields is None:
            extracted_fields = []

        field_matches = re.findall(r'<field name="([^"]+)"', xml_string)
        if not field_matches:
            return True, None

        errors = []
        for field in field_matches:
            if field in self.STATIC_FIELDS:
                errors.append(f"Static field '{field}' must use <{field}> tag")
            elif field not in extracted_fields and field != "full_log":
                errors.append(f"Field '{field}' not extracted by decoder '{decoder_name}'. Available: {extracted_fields}")

        if errors:
            return False, "; ".join(errors)
        return True, None

    def _get_rule_by_id(self, rule_id: str) -> Document | None:
        chroma_filter = build_chroma_filter({"type": "rule", "rule_id": rule_id})
        results = self.db.similarity_search("", k=1, filter=chroma_filter)
        if results:
            return results[0]
        if hasattr(self, '_in_memory_parents') and rule_id in self._in_memory_parents:
            return self._in_memory_parents[rule_id]
        return None

    def _get_decoder_by_name(self, decoder_name: str) -> Document | None:
        chroma_filter = build_chroma_filter({"type": "decoder", "decoder_name": decoder_name})
        results = self.db.similarity_search("", k=1, filter=chroma_filter)
        return results[0] if results else None

    def _find_valid_parent(self, platform: str) -> str | None:
        chroma_filter = build_chroma_filter({"type": "rule", "platform": platform, "has_children": True})
        results = self.db.similarity_search("", k=3, filter=chroma_filter)
        if results:
            return results[0].metadata.get("rule_id")
        return None

    def is_new_rule_type(self, original_decoder: str, retrieved_rules: list,
                         valid_parent_count: int, category: str) -> tuple[bool, str]:
        reasons = []
        if original_decoder == "unknown" and valid_parent_count == 0:
            reasons.append("unknown_decoder_no_parents")
        relevant = sum(1 for r in retrieved_rules
                       if category != "unknown" and category.lower() in (r.metadata.get("category", "") or "").lower())
        if relevant == 0 and len(retrieved_rules) > 0:
            reasons.append(f"no_relevant_rules_for_{category}")
        is_new = len(reasons) > 0
        return is_new, ", ".join(reasons) if is_new else "existing"

    def validate_decoder(self, decoder_xml: str, sigma_fields: list, decoder_name: str) -> tuple[bool, list[str], dict]:
        self.reviews = []
        coverage = {"covered": [], "missing": [], "mapped": {}}

        valid, error = self._validate_xml_syntax(decoder_xml)
        if not valid:
            self.reviews.append(f"Decoder XML syntax error: {error}")
            return False, self.reviews, coverage

        root = ET.fromstring(decoder_xml)
        has_prematch = root.find("prematch") is not None or root.get("prematch") is not None
        has_program = root.find("program_name") is not None
        has_parent = root.get("parent") is not None
        if not has_prematch and not has_program and not has_parent:
            self.reviews.append("Decoder must have <prematch> or <program_name>")

        extracted_fields = []
        for order_elem in root.iter("order"):
            if order_elem.text:
                extracted_fields.extend([f.strip() for f in order_elem.text.split(",")])
        for regex_elem in root.iter("regex"):
            if regex_elem.text:
                extracted_fields.extend(re.findall(r"\?P<([^>]+)>", regex_elem.text))
        extracted_fields = list(set([f for f in extracted_fields if f]))

        covered, missing, mapped = [], [], {}
        for sf in sigma_fields:
            sf_lower = sf.lower()
            found = False
            for ef in extracted_fields:
                ef_lower = ef.lower()
                if (sf_lower in ef_lower or ef_lower in sf_lower or
                    sf_lower.replace("image", "command") in ef_lower):
                    covered.append(sf)
                    mapped[sf] = ef
                    found = True
                    break
            if not found:
                missing.append(sf)

        coverage = {"covered": covered, "missing": missing, "mapped": mapped, "extracted_fields": extracted_fields}
        if missing:
            self.reviews.append(f"Decoder missing fields: {missing}")

        return len(self.reviews) == 0, self.reviews, coverage

    def add_in_memory_parent(self, parent_doc: Document):
        if not hasattr(self, '_in_memory_parents'):
            self._in_memory_parents = {}
        parent_id = parent_doc.metadata.get("rule_id")
        if parent_id:
            self._in_memory_parents[parent_id] = parent_doc