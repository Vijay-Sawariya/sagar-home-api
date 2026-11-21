"""Shared property captures, using the same address/locality identity as monthly books.

Old conflicts resolve per field: newest lead ID, then newest book month/entry ID.
Reads also reconcile old captures without requiring a destructive data migration.
"""
from pymysql.err import MySQLError

FIELDS = ('Property_locationUrl', 'building_facing')


def identity(row):
    # Imported lazily because monthly_inventory also uses this module.
    from monthly_inventory import address_key
    key = tuple(address_key(row.get(field)) for field in ('address', 'location'))
    return key if all(key) else None


def capture_groups(cursor):
    try:
        cursor.execute("SELECT id,address,location,Property_locationUrl,building_facing FROM leads WHERE COALESCE(is_deleted,0)=0 AND LOWER(TRIM(lead_type)) IN ('seller','builder','owner','landlord','rent','agent') ORDER BY id DESC")
        leads = list(cursor.fetchall())
        cursor.execute("SELECT e.id,e.address,e.location,e.Property_locationUrl,e.building_facing FROM monthly_inventory_entries e JOIN monthly_inventory_books b ON b.id=e.book_id WHERE e.is_deleted=0 ORDER BY b.book_month DESC,e.id DESC")
        entries = list(cursor.fetchall())
    except MySQLError as error:
        if error.args and error.args[0] in (1146, 1054):
            return {}  # Older deployments without monthly books remain usable.
        raise
    groups = {}
    for table, rows in (('leads', leads), ('monthly_inventory_entries', entries)):
        for row in rows:
            key = identity(row)
            if key:
                group = groups.setdefault(key, {'values': {}, 'records': []})
                group['records'].append((table, row['id']))
                for field in FIELDS:
                    value = row.get(field)
                    if isinstance(value, str) and value.strip():
                        group['values'].setdefault(field, value.strip())
    return groups


def hydrate_captures(cursor, rows):
    if not rows:
        return
    groups = capture_groups(cursor)
    for row in rows:
        if 'lead_type' in row and str(row['lead_type']).strip().lower() not in ('seller', 'builder', 'owner', 'landlord', 'rent', 'agent'):
            continue
        group = groups.get(identity(row))
        if group:
            row.update(group['values'])


def sync_capture(cursor, table, record_id, changes):
    changes = {field: changes[field] for field in FIELDS if field in changes}
    if not changes:
        return
    groups = capture_groups(cursor)
    for group in groups.values():
        if (table, record_id) not in group['records']:
            continue
        for target in ('leads', 'monthly_inventory_entries'):
            ids = sorted(row_id for name, row_id in group['records'] if name == target)
            if ids:
                cursor.execute('UPDATE ' + target + ' SET ' + ','.join('`' + field + '`=%s' for field in changes)
                               + ' WHERE id IN (' + ','.join(['%s'] * len(ids)) + ')',
                               [*changes.values(), *ids])
        break
