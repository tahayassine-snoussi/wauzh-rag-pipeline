"""
Shared utilities for the Sigma -> Wazuh pipeline.
"""


def build_chroma_filter(filter_dict: dict) -> dict:
    """
    Build ChromaDB-compatible filter from simple key-value pairs.

    ChromaDB requires: {"$and": [{"field": {"$eq": "value"}}]}
    We accept: {"field": "value", "field2": "value2"}

    Args:
        filter_dict: Simple dict of field -> value pairs

    Returns:
        ChromaDB-compatible filter dict
    """
    if not filter_dict:
        return {}

    conditions = []
    for key, value in filter_dict.items():
        conditions.append({key: {"$eq": value}})

    if len(conditions) == 1:
        return conditions[0]
    return {"$and": conditions}