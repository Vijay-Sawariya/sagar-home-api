"""Read/convert the web application's monthly books; deliberately no upload routes."""
import logging
from typing import List, Optional
from contextlib import contextmanager
from urllib.parse import urlparse
from pymysql.err import MySQLError
import math
import re
import tempfile
import unicodedata
from datetime import datetime, timezone
from fastapi import Body, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

CATEGORIES = ('residential_sale', 'residential_rent', 'commercial_sale', 'commercial_rent')


def require_access(user):
    if not user.get('id') or user.get('username') != 'vsawariya':
        raise HTTPException(403, 'Monthly inventory books are available only to vsawariya.')


def address_key(value):
    return ''.join(c for c in str(value or '').strip().lower()
                   if not c.isspace() and unicodedata.category(c) not in ('Zs', 'Zl', 'Zp', 'Pd') and c not in ',.')


def phone_key(value):
    digits = re.sub(r'\D', '', str(value or ''))
    for length, prefix in ((14, '0091'), (12, '91'), (11, '0')):
        if len(digits) == length and digits.startswith(prefix):
            return digits[len(prefix):]
    return digits


def duplicates(data, existing):
    sale = data['lead_type'] in ('seller', 'builder', 'owner')
    group = ('seller', 'builder', 'owner') if sale else ('landlord', 'rent')
    return (str(existing.get('lead_type', '')).strip().lower() in group
            and (sale or phone_key(data.get('phone')) == phone_key(existing.get('phone')))
            and all(address_key(data.get(k)) and address_key(data.get(k)) == address_key(existing.get(k))
                    for k in ('address', 'location')))


def conversion_data(payload, entry, user, lead_model):
    try:
        model = lead_model(**payload)
        data = model.model_dump() if hasattr(model, 'model_dump') else model.dict()
    except Exception:
        raise HTTPException(422, 'Check the inventory form values.')
    data.pop('creation_context', None)
    for key, maximum in (('name', 255), ('phone', 20), ('location', 255), ('address', 255), ('floor', 40), ('bhk', 20)):
        data[key] = str(data.get(key) or '').strip()
        if len(data[key].encode('utf-8')) > maximum:
            raise HTTPException(422, 'Please shorten ' + key + '.')
    if any(not data[k] for k in ('name', 'location', 'address')):
        raise HTTPException(422, 'Name, location and address are required.')
    if not re.fullmatch(r'\+?[0-9 ()-]{8,22}', data['phone']) or len(re.sub(r'\D', '', data['phone'])) < 10:
        raise HTTPException(422, 'Enter one primary phone number with at least 10 digits.')
    if data['lead_type'] not in ('seller', 'builder', 'landlord') or data.get('unit') not in ('CR', 'L', 'K'):
        raise HTTPException(422, 'Choose a valid inventory type and price unit.')
    if data.get('property_type') not in ('Builder Floor', 'Apartment', 'Commercial', 'Office Space', 'Shop', 'Plot', 'Villa', 'Farm House'):
        raise HTTPException(422, 'Choose a valid property type.')
    for field in ('builder_id', 'car_parking_number'):
        if data.get(field) is not None and not 0 <= data[field] <= 2147483647:
            raise HTTPException(422, 'Enter a valid ' + field + '.')
    if data.get('Property_locationUrl'):
        url = urlparse(data['Property_locationUrl'])
        if url.scheme not in ('https', 'http') or not url.netloc:
            raise HTTPException(422, 'Enter a valid Google Map URL.')
    if data.get('possession_on'):
        try:
            datetime.strptime(data['possession_on'], '%Y-%m-%d')
        except ValueError:
            raise HTTPException(422, 'Choose a valid possession date.')
    if data.get('property_age') and (not data['property_age'].isdigit() or not 1 <= int(data['property_age']) <= 50):
        raise HTTPException(422, 'Choose a valid property age.')
    if data.get('lift_available') not in (None, '', 'Yes', 'No'):
        raise HTTPException(422, 'Choose a valid lift option.')
    area_unit = payload.get('area_unit') or entry.get('area_unit') or 'YD'
    if area_unit not in ('YD', 'SQFT', 'SQM', 'ACRE'):
        raise HTTPException(422, 'Choose a valid area unit.')
    for key in ('area_size', 'budget_min', 'budget_max'):
        if data.get(key) not in (None, ''):
            try:
                number = float(data[key])
                if not math.isfinite(number) or number < 0:
                    raise ValueError()
            except (ValueError, TypeError):
                raise HTTPException(422, 'Enter a valid non-negative ' + key + '.')
    data['area_size'] = str(data['area_size']) if data.get('area_size') not in (None, '') else None
    data['area_unit'] = area_unit
    data['name'] = data['name'].title()
    if data['area_size'] and len(data['area_size']) > 20:
        raise HTTPException(422, 'Area size is too long.')
    prices = []
    selected = [f.strip() for f in data['floor'].split(',')]
    for row in data.pop('floor_pricing', None) or []:
        if row.get('floor') not in selected:
            continue
        try:
            amount = float(row.get('price'))
            if not math.isfinite(amount) or amount < 0:
                raise ValueError()
        except (ValueError, TypeError):
            raise HTTPException(422, 'Enter valid floor prices.')
        prices.append((row['floor'], amount))
    if prices:
        data['budget_min'] = min(p[1] for p in prices)
        data['budget_max'] = max(p[1] for p in prices)
    if data.get('budget_min') is not None and data.get('budget_max') is not None and data['budget_min'] > data['budget_max']:
        raise HTTPException(422, 'Maximum price must be at least the minimum.')
    data['source_type'] = 'Inventory'
    data['notes'] = (data.get('notes') or '').strip()
    data.update(created_by=user['id'], created_at=datetime.now(timezone.utc).replace(tzinfo=None))
    return {k: v for k, v in data.items() if v is not None}, prices


def convert(conn, entry_id, payload, user, lead_model):
    require_access(user)
    conn.begin()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT e.*,b.book_month,b.category FROM monthly_inventory_entries e JOIN monthly_inventory_books b ON b.id=e.book_id WHERE e.id=%s FOR UPDATE', (entry_id,))
        entry = cursor.fetchone()
        if not entry or entry.get('is_deleted'):
            raise HTTPException(404, 'Book entry was not found or has been deleted.')
        if entry.get('converted_lead_id'):
            conn.commit()
            return {'id': entry['converted_lead_id'], 'already_converted': True}
        data, prices = conversion_data(payload, entry, user, lead_model)
        if data.get('builder_id'):
            cursor.execute('SELECT id FROM builders WHERE id=%s AND COALESCE(is_deleted,0)=0', (data['builder_id'],))
            if not cursor.fetchone():
                raise HTTPException(422, 'Select an available builder.')
        cursor.execute("SHOW TABLES LIKE 'telecaller\\_leads'")
        stores = ['leads', 'telecaller_leads'] if cursor.fetchone() else ['leads']
        for table in stores:
            cursor.execute(f"SELECT id,phone,address,location,lead_type FROM {table} WHERE COALESCE(is_deleted,0)<>1 AND LOWER(TRIM(lead_type)) IN ('seller','builder','owner','landlord','rent') ORDER BY id")
            for existing in cursor.fetchall():
                if duplicates(data, existing):
                    raise HTTPException(409, f"Duplicate inventory already exists: Lead #{existing['id']} ({table}). Use View Lead when available.")
        cursor.execute('INSERT INTO leads (' + ','.join('`' + k + '`' for k in data) + ') VALUES (' + ','.join(['%s'] * len(data)) + ')', list(data.values()))
        lead_id = cursor.lastrowid
        for floor, amount in prices:
            cursor.execute('INSERT INTO inventory_floor_pricing (lead_id,floor_label,floor_amount) VALUES (%s,%s,%s)', (lead_id, floor, amount))
        cursor.execute('UPDATE monthly_inventory_entries SET converted_lead_id=%s,converted_at=NOW(),converted_by=%s WHERE id=%s', (lead_id, user['id'], entry_id))
        conn.commit()
        return {'id': lead_id, 'already_converted': False}
    except Exception:
        conn.rollback()
        raise


def soft_delete(conn, entry_id, user):
    require_access(user)
    conn.begin()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT e.identity_hash,b.category FROM monthly_inventory_entries e JOIN monthly_inventory_books b ON b.id=e.book_id WHERE e.id=%s', (entry_id,))
        entry = cursor.fetchone()
        if not entry:
            raise HTTPException(404, 'Book entry was not found.')
        # The web importer locks this same category/identity key before inserting.
        cursor.execute('INSERT INTO monthly_inventory_exclusions (category,identity_hash,source_entry_id,deleted_by) VALUES (%s,%s,%s,%s) ON DUPLICATE KEY UPDATE identity_hash=VALUES(identity_hash)', (entry['category'], entry['identity_hash'], entry_id, user['id']))
        cursor.execute('UPDATE monthly_inventory_entries e JOIN monthly_inventory_books b ON b.id=e.book_id SET e.is_deleted=1,e.deleted_at=NOW(),e.deleted_by=%s WHERE b.category=%s AND e.identity_hash=%s AND e.is_deleted=0', (user['id'], entry['category'], entry['identity_hash']))
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def register_routes(router, get_db, get_current_user, lead_model):
    @contextmanager
    def monthly_db():
        try:
            with get_db() as conn:
                yield conn
        except MySQLError as error:
            logging.exception('Monthly inventory API database operation failed')
            if error.args and error.args[0] in (1146, 1054):
                raise HTTPException(503, 'Monthly books are not configured on this API database. Deploy the web monthly inventory migrations first.')
            raise HTTPException(503, 'Monthly inventory is temporarily unavailable. Please try again.')

    def authorized(user=Depends(get_current_user)):
        require_access(user)
        return user

    @router.get('/monthly-inventory')
    def list_books(month: str = '', category: str = '', search: str = '', page: int = Query(1, ge=1), location: str = '', locations: Optional[List[str]] = Query(None), address: str = '', owner_name: str = '', phone: str = '', floor: str = '', min_area: float = Query(None, ge=0), max_area: float = Query(None, ge=0), user=Depends(authorized)):
        if month and not re.fullmatch(r'\d{4}-(0[1-9]|1[0-2])', month):
            raise HTTPException(422, 'Select a valid month.')
        if category and category not in CATEGORIES:
            raise HTTPException(422, 'Select a valid category.')
        if min_area is not None and max_area is not None and min_area > max_area:
            raise HTTPException(422, 'Minimum area must not exceed maximum area.')
        with monthly_db() as conn:
            cursor = conn.cursor()
            where, args = ['e.is_deleted=0'], []
            if month:
                where.append("DATE_FORMAT(b.book_month,'%%Y-%%m')=%s"); args.append(month)
            if category:
                where.append('b.category=%s'); args.append(category)
            if search.strip():
                where.append("CONCAT_WS(' ',e.owner_name,e.phone,e.address,e.location,e.note) LIKE %s")
                args.append('%' + search.strip()[:200] + '%')
            selected_locations = list(dict.fromkeys(value.strip() for value in (locations or []) if value.strip()))
            if selected_locations:
                where.append('e.location IN (' + ','.join(['%s'] * len(selected_locations)) + ')')
                args.extend(selected_locations)
            for column, value in [('location', location), ('address', address), ('owner_name', owner_name), ('phone', phone), ('floor', floor)]:
                if value.strip():
                    where.append(f'e.{column} LIKE %s')
                    args.append('%' + value.strip()[:200] + '%')
            for operator, value in [('>=', min_area), ('<=', max_area)]:
                if value is not None:
                    where.append(f"NULLIF(e.area_size,'') {operator} %s")
                    args.append(value)
            base = ' FROM monthly_inventory_entries e JOIN monthly_inventory_books b ON b.id=e.book_id' + (' WHERE ' + ' AND '.join(where) if where else '')
            previous = '(SELECT MAX(pb.book_month) FROM monthly_inventory_books pb WHERE pb.category=b.category AND pb.book_month<b.book_month)'
            repeated = f'EXISTS (SELECT 1 FROM monthly_inventory_entries pe JOIN monthly_inventory_books pb ON pb.id=pe.book_id WHERE pb.category=b.category AND pb.book_month={previous} AND pe.identity_hash=e.identity_hash)'
            cursor.execute('SELECT COUNT(*) AS total' + base, args)
            total = cursor.fetchone()['total']
            cursor.execute(f"SELECT e.*,b.book_month,b.category,CASE WHEN {previous} IS NULL THEN 'First book' WHEN {repeated} THEN 'Repeated' ELSE 'New' END AS entry_status" + base + ' ORDER BY b.book_month DESC,e.location,e.id LIMIT 40 OFFSET %s', args + [(page-1)*40])
            rows = list(cursor.fetchall())
            matches = {}
            if rows:
                cursor.execute("SELECT id,address,location FROM leads WHERE COALESCE(is_deleted,0)=0 AND LOWER(lead_type) IN ('seller','builder','owner','landlord','agent') ORDER BY id DESC")
                for lead in cursor.fetchall():
                    matches.setdefault((address_key(lead['address']), address_key(lead['location'])), lead['id'])
            cursor.execute('SELECT id,book_month,category FROM monthly_inventory_pdfs')
            pdfs = {(str(p['book_month']), p['category']): p['id'] for p in cursor.fetchall()}
            for row in rows:
                key = (address_key(row['address']), address_key(row['location']))
                row['matching_lead_id'] = matches.get(key) if all(key) else None
                row['pdf_id'] = pdfs.get((str(row['book_month']), row['category']))
            cursor.execute("SELECT DISTINCT location FROM monthly_inventory_entries WHERE is_deleted=0 AND location IS NOT NULL AND TRIM(location)<>'' ORDER BY location")
            locations_available = [row['location'] for row in cursor.fetchall()]
            cursor.execute("SELECT DISTINCT DATE_FORMAT(book_month,'%Y-%m') AS month FROM monthly_inventory_books ORDER BY month DESC")
            return {'items': rows, 'total': total, 'page': page, 'has_more': page*40 < total,
                    'months': [m['month'] for m in cursor.fetchall()], 'locations': locations_available}

    @router.post('/monthly-inventory/{entry_id}/status')
    def update_status(entry_id: int, payload: dict = Body(...), user=Depends(authorized)):
        status = payload.get('inventory_status')
        if status not in ('Available', 'Sold', 'Hold', 'Invalid'):
            raise HTTPException(422, 'Select a valid inventory status.')
        with monthly_db() as conn:
            c = conn.cursor()
            c.execute("SHOW COLUMNS FROM monthly_inventory_entries LIKE 'inventory_status'")
            if not c.fetchone():
                raise HTTPException(503, 'Install the web monthly inventory status migration first.')
            conn.begin()
            try:
                c.execute('SELECT id FROM monthly_inventory_entries WHERE id=%s AND is_deleted=0 FOR UPDATE', (entry_id,))
                if not c.fetchone():
                    raise HTTPException(404, 'Inventory entry not found.')
                c.execute('UPDATE monthly_inventory_entries SET inventory_status=%s,status_changed_at=NOW(),status_changed_by=%s WHERE id=%s', (status, user['id'], entry_id))
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return {'inventory_status': status}

    @router.post('/monthly-inventory/{entry_id}/delete')
    def delete_book(entry_id: int, user=Depends(authorized)):
        with monthly_db() as conn:
            soft_delete(conn, entry_id, user)
        return {'deleted': True}

    @router.post('/monthly-inventory/{entry_id}/convert')
    def convert_book(entry_id: int, payload: dict = Body(...), user=Depends(authorized)):
        with monthly_db() as conn:
            return convert(conn, entry_id, payload, user, lead_model)

    @router.get('/monthly-inventory/pdfs/{pdf_id}')
    def view_pdf(pdf_id: int, user=Depends(authorized)):
        # Spool in small DB packets: large books never occupy 100 MB of API RAM.
        document = tempfile.SpooledTemporaryFile(max_size=1024*1024)
        try:
            with monthly_db() as conn:
                conn.begin()
                cursor = conn.cursor()
                cursor.execute('SELECT OCTET_LENGTH(content) AS size FROM monthly_inventory_pdfs WHERE id=%s LOCK IN SHARE MODE', (pdf_id,))
                row = cursor.fetchone()
                if not row:
                    raise HTTPException(404, 'Book PDF is not available.')
                for offset in range(1, row['size'] + 1, 1024*1024):
                    cursor.execute('SELECT SUBSTRING(content,%s,%s) AS chunk FROM monthly_inventory_pdfs WHERE id=%s', (offset, 1024*1024, pdf_id))
                    document.write(cursor.fetchone()['chunk'])
                conn.commit()
            document.seek(0)
        except Exception:
            document.close()
            raise
        def chunks():
            try:
                while True:
                    chunk = document.read(64*1024)
                    if not chunk:
                        break
                    yield chunk
            finally:
                document.close()
        return StreamingResponse(chunks(), media_type='application/pdf', headers={
            'Content-Disposition': f'inline; filename="monthly-book-{pdf_id}.pdf"',
            'Content-Length': str(row['size']), 'Cache-Control': 'private, no-store'})
