"""Shared natural address ordering, evaluated before database pagination."""

def address_order_sql(column: str) -> str:
    # Column names are supplied only by application code.
    address = f"LOWER(TRIM(COALESCE({column}, '')))"
    normalized = f"REGEXP_REPLACE({address}, '[[:space:]/-]+', '-')"
    parts = [f"({address} = '') ASC"]
    for i in range(1, 7):
        token = (f"CASE WHEN 1 + CHAR_LENGTH({normalized}) - "
                 f"CHAR_LENGTH(REPLACE({normalized}, '-', '')) >= {i} THEN "
                 f"SUBSTRING_INDEX(SUBSTRING_INDEX({normalized}, '-', {i}), '-', -1) ELSE '' END")
        prefix = f"REGEXP_REPLACE({token}, '[0-9].*$', '')"
        number = f"REGEXP_REPLACE({token}, '^[^0-9]*', '')"
        parts.extend([f"{prefix} ASC", f"CAST({number} AS UNSIGNED) ASC",
                      f"REGEXP_REPLACE({number}, '^[0-9]+', '') ASC"])
    parts.append(f"{address} ASC")
    return ', '.join(parts)
