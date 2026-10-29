"""Inventory-to-client comparisons shared with the web recipient matching rules."""
import re
import unicodedata


def split_values(values):
    if not isinstance(values, (list, tuple)):
        values = [values]
    return [part.strip() for value in values for part in str(value or '').split(',') if part.strip()]


def locations(values):
    return {''.join(c for c in value.lower() if not (c.isspace() or unicodedata.category(c) in ('Zs', 'Zl', 'Zp', 'Pd') or c in ',.')) for value in split_values(values)} - {''}


def floors(values):
    aliases = {'ground':'gf', 'groundfloor':'gf', 'first':'ff', 'firstfloor':'ff',
               'second':'sf', 'secondfloor':'sf', 'third':'tf', 'thirdfloor':'tf',
               'basement':'bmt', 'bsmt':'bmt', 'lowerground':'lgf', 'lowergroundfloor':'lgf',
               'terrace':'terr', 'terrece':'terr', 't':'terr'}
    tokens = set()
    for value in split_values(values):
        token = re.sub(r'[\s./]+', '', value.lower())
        if token in ('any', 'all', 'anyfloor', 'allfloors', 'nopreference'):
            return set()
        if token == 'tft':
            token = 'tf+terr'
        if token:
            tokens.add('+'.join(aliases.get(part, part) for part in token.split('+')))
    return tokens


def number(value):
    try:
        return float(value) if value not in (None, '') else None
    except (ValueError, TypeError):
        return None


def area_in_yards(lead):
    area = number(lead.get('area_size'))
    if area is None:
        return None
    unit = str(lead.get('area_unit') or 'YD').strip().upper()
    return area * {'SQFT': 1 / 9, 'SQM': 1.1959900463, 'ACRE': 4840}.get(unit, 1)


def in_crores(amount, unit):
    return (number(amount) or 0) * {'L': 0.01, 'K': 0.0001}.get(str(unit).strip().upper(), 1)


def target_types(inventory, match_context=''):
    lead_type = str(inventory.get('lead_type') or '').strip().lower()
    if lead_type == 'agent':
        return ['tenant', 'rent'] if match_context == 'rent' else ['buyer']
    if lead_type in ('seller', 'builder'):
        return ['buyer']
    if lead_type in ('landlord', 'owner'):
        return ['tenant', 'rent']
    return []


def defaults(inventory, pricing):
    area = area_in_yards(inventory)
    amounts = [number(row.get('floor_amount')) for row in pricing]
    amounts = [amount for amount in amounts if amount and amount > 0]
    return {
        'locations': split_values(inventory.get('location')),
        'floors': list(dict.fromkeys(split_values(inventory.get('floor')) + [row['floor_label'] for row in pricing if row.get('floor_label')])),
        'area_min': max(0, area - 50) if area and area > 0 else None,
        'area_max': area + 50 if area and area > 0 else None,
        'budget_min': min(amounts) if amounts else (number(inventory.get('budget_min')) or None),
        'budget_max': max(amounts) if amounts else (number(inventory.get('budget_max')) or None),
    }


def reasons(inventory, candidate, filters):
    result = []
    selected_locations = locations(filters['locations'])
    if selected_locations:
        if not selected_locations.intersection(locations(candidate.get('location'))):
            return None
        result.append('Location')
    area = area_in_yards(candidate)
    if area and area > 0:
        if filters['area_min'] is not None and area < filters['area_min']:
            return None
        if filters['area_max'] is not None and area > filters['area_max']:
            return None
        if filters['area_min'] is not None or filters['area_max'] is not None:
            result.append('Area')
    default_unit = 'L' if str(candidate.get('lead_type') or '').strip().lower() in ('tenant', 'rent') else 'CR'
    candidate_unit = str(candidate.get('unit') or '').strip() or default_unit
    inventory_unit = str(inventory.get('unit') or '').strip() or default_unit
    lower = in_crores(candidate.get('budget_min'), candidate_unit)
    upper = in_crores(candidate.get('budget_max'), candidate_unit)
    if filters['budget_min'] is not None or filters['budget_max'] is not None:
        inv_lower = in_crores(filters['budget_min'], inventory_unit) if filters['budget_min'] is not None else 0
        inv_upper = in_crores(filters['budget_max'], inventory_unit) if filters['budget_max'] is not None else float('inf')
        if lower > 0 or upper > 0:
            if inv_lower > (upper * 1.2 if upper > 0 else float('inf')) or inv_upper < lower * 0.8:
                return None
            result.append('Budget')
    selected_floors = floors(filters['floors'])
    candidate_floors = floors(candidate.get('floor'))
    if selected_floors and candidate_floors:
        if not selected_floors.intersection(candidate_floors):
            return None
        result.append('Floor')
    return result
