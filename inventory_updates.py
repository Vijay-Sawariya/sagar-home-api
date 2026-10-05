"""Inventory-only mutations, compatible with the web LMS report vocabulary."""
import hashlib
import json
import re
from decimal import Decimal


def floors(snapshot):
    return list(dict.fromkeys([v.strip() for v in snapshot['floor'].split(',') if v.strip()] +
                              [r['floor_label'] for r in snapshot['prices']]))


def version(snapshot):
    return hashlib.sha256(json.dumps(snapshot, sort_keys=True, default=str).encode()).hexdigest()


def plan(snapshot, data):
    if set(data) - {'inventory_version', 'floors', 'property_price', 'entire_sold', 'call_notes'}:
        raise ValueError('Unsupported inventory fields.')
    if not isinstance(data.get('call_notes'), str) or not 1 <= len(data['call_notes'].strip()) <= 5000:
        raise ValueError('Enter call verification notes (up to 5000 characters).')
    if type(data.get('entire_sold', False)) is not bool:
        raise ValueError('Invalid sold flag.')
    labels = floors(snapshot)
    rows = data.get('floors', [])
    if not isinstance(rows, list) or len(rows) != len(labels):
        raise ValueError('Refresh to load all current floors.')
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) - {'label', 'price', 'sold'}:
            raise ValueError('Invalid floor update.')
        label = row.get('label')
        if not isinstance(label, str) or label not in labels or label in seen:
            raise ValueError('Invalid or duplicate floor. Reopen the popup.')
        if type(row.get('sold', False)) is not bool:
            raise ValueError('Invalid sold flag.')
        seen.add(label)
    if data.get('entire_sold'):
        return [('sold_all', '', None)] if snapshot['lead_status'] != 'Sold' else []
    if snapshot['lead_status'] == 'Sold':
        raise ValueError('Sold inventory cannot be reopened from this popup.')
    existing = {r['floor_label']: r['floor_amount'] for r in snapshot['prices']}
    changes = []
    def price_change(raw, old, kind, label):
        raw = str(raw if raw is not None else '').strip()
        if not raw and old is None:
            return
        if not re.fullmatch(r'\d{1,13}(\.\d{1,2})?', raw) or Decimal(raw) <= 0:
            raise ValueError('Enter a positive price with at most two decimal places.')
        if old is None or Decimal(raw) != Decimal(str(old)):
            changes.append((kind, label, raw))
    for row in rows:
        label = row['label']
        if row.get('sold'):
            changes.append(('sold_floor', label, None))
        else:
            price_change(row.get('price'), existing.get(label), 'price_floor', label)
    if not labels:
        price_change(data.get('property_price'), snapshot['budget_max'], 'price_all', '')
    return changes
