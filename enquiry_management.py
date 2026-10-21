"""Mobile workflow over the web LMS sheet_enquiries registry (not legacy inventory)."""
import json
import math
import re
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from fastapi import Body, Depends, HTTPException, Query

STATUSES = ('New', 'Contacted', 'Qualified', 'Nurture', 'Disqualified', 'Invalid')
OUTCOMES = ('Connected', 'No answer', 'Busy', 'Wrong number', 'Message sent')
DUE = """e.id IN (SELECT a.entity_id FROM actions a WHERE a.entity_type='sheet_enquiry' AND a.status IN ('Pending','Missed')
 AND TIMESTAMP(a.due_date,COALESCE(a.due_time,'00:00:00'))<=NOW())"""


def manager(user):
    return str(user.get('role', '')).strip().lower() in ('admin', 'manager')


def can_convert(user):
    return str(user.get('role', '')).strip().lower() in ('admin', 'sr agent')


def scope(user):
    return ('1=1', []) if manager(user) else ('e.assigned_to=%s', [user['id']])


def phone_key(value):
    digits = re.sub(r'\D', '', str(value or ''))
    for prefix, length in (('0091', 14), ('91', 12), ('0', 11)):
        if len(digits) == length and digits.startswith(prefix):
            return digits[len(prefix):]
    return digits


def phone_expr():
    expr = "COALESCE(phone,'')"
    for char in ("' '", "'+'", "'-'", "'('", "')'", "'.'", 'CHAR(9)', 'CHAR(10)', 'CHAR(13)'):
        expr = f'REPLACE({expr},{char},\'\')'
    return expr


def unpack(value, default=None):
    try:
        return json.loads(value) if value else (default if default is not None else {})
    except (TypeError, ValueError):
        return default if default is not None else {}


def wire(row):
    # MySQL TIME is returned as timedelta; FastAPI's default encoder cannot encode it.
    result = {k: str(v) if isinstance(v, (datetime, timedelta)) else v for k, v in row.items()}
    if 'original_json' in row:
        result['original'] = unpack(row.get('original_json'))
        result['current'] = unpack(row.get('current_json'))
        result['qualification'] = unpack(row.get('qualification_json'))
        result['source'] = ('Website-Enquiry' if row.get('spreadsheet_id') == 'https://sagarhome.com'
                            and row.get('worksheet') == 'Website-Enquiry' else 'Meta Ad')
        result['source_changed'] = row.get('original_json') != row.get('current_json')
        for key in ('original_json', 'current_json', 'qualification_json'):
            result.pop(key, None)
    return result


def get_row(cursor, enquiry_id, user, lock=False):
    where, args = scope(user)
    cursor.execute(f'SELECT e.* FROM sheet_enquiries e WHERE e.id=%s AND {where}' + (' FOR UPDATE' if lock else ''), [enquiry_id] + args)
    row = cursor.fetchone()
    if not row:
        raise HTTPException(404, 'Enquiry not found or access denied.')
    return row


def audit(cursor, enquiry_id, user, event, details):
    cursor.execute('INSERT INTO sheet_enquiry_activities (enquiry_id,actor_id,event_type,details,created_at) VALUES (%s,%s,%s,%s,NOW())',
                   (enquiry_id, user['id'], event, json.dumps(details, ensure_ascii=False)))


def qualification(payload):
    fields = ('name', 'phone', 'lead_type', 'lead_source', 'lead_status', 'location', 'property_type',
              'max_possession_wait_months', 'area_size', 'floor', 'bhk', 'building_facing',
              'required_amenities', 'budget_min', 'budget_max', 'unit', 'notes')
    q = {}
    for key in fields:
        value = payload.get(key, '')
        if isinstance(value, list) and key in ('location', 'floor', 'bhk', 'building_facing', 'required_amenities'):
            if any(isinstance(v, (dict, list)) for v in value):
                raise HTTPException(422, 'Invalid ' + key)
            value = ','.join(dict.fromkeys(str(v).strip() for v in value))
        if isinstance(value, (dict, list)):
            raise HTTPException(422, 'Invalid ' + key)
        q[key] = str(value if value is not None else '').strip()
        if len(q[key].encode()) > (2000 if key == 'notes' else 255):
            raise HTTPException(422, 'Field is too long: ' + key)
    for key in ('name', 'phone', 'lead_type', 'location', 'property_type', 'budget_min', 'budget_max', 'unit'):
        if not q[key]:
            raise HTTPException(422, 'Complete ' + key.replace('_', ' ') + '.')
    for key, choices in (('lead_type', ('buyer', 'tenant')), ('lead_status', ('', 'New', 'Hot', 'Pending', 'Warm', 'Cold', 'Follow Up', 'Closed/Lost')), ('unit', ('CR', 'L', 'K'))):
        if q[key] not in choices:
            raise HTTPException(422, 'Choose a valid ' + key.replace('_', ' ') + '.')
    for key in ('budget_min', 'budget_max', 'area_size', 'max_possession_wait_months'):
        if q[key]:
            try:
                n = float(q[key])
                if not math.isfinite(n) or not 0 <= n <= 999999999:
                    raise ValueError()
            except (ValueError, TypeError):
                raise HTTPException(422, 'Enter a valid non-negative ' + key.replace('_', ' ') + '.')
    if q['max_possession_wait_months'] and (not q['max_possession_wait_months'].isdigit() or int(q['max_possession_wait_months']) > 65535):
        raise HTTPException(422, 'Maximum wait must be a whole number from 0 to 65535.')
    if float(q['budget_min']) > float(q['budget_max']):
        raise HTTPException(422, 'Maximum budget must be at least the minimum.')
    if not re.fullmatch(r'[+0-9() .-]+', q['phone']) or not 10 <= len(re.sub(r'\D', '', q['phone'])) <= 15:
        raise HTTPException(422, 'Phone must contain 10 to 15 digits.')
    q['budget'] = q['budget_min'] + ' – ' + q['budget_max'] + ' ' + q['unit']
    return q


def future_due(value):
    try:
        parsed = datetime.strptime(str(value), '%Y-%m-%dT%H:%M')
        if parsed.strftime('%Y-%m-%dT%H:%M') != value or parsed <= datetime.now(ZoneInfo('Asia/Kolkata')).replace(tzinfo=None):
            raise ValueError()
        return parsed
    except (ValueError, TypeError):
        raise HTTPException(422, 'Choose a future follow-up date and time (Asia/Kolkata).')


def register_routes(router, get_db, get_user, columns, table_exists, active_users):
    def authorized_user(user: dict = Depends(get_user)):
        # Deep links/API calls must respect the same mobile feature switch as navigation.
        with get_db() as conn:
            cursor = conn.cursor()
            if table_exists(cursor, 'user_mobile_feature_flags'):
                cursor.execute("SELECT feature_key,is_enabled FROM user_mobile_feature_flags WHERE user_id=%s AND feature_key IN ('enquiry_management','__default__')", (user['id'],))
                flags = {r['feature_key']: bool(r['is_enabled']) for r in cursor.fetchall()}
                if not flags.get('enquiry_management', flags.get('__default__', True)):
                    raise HTTPException(403, 'Enquiry Management access is disabled for your account.')
        return user

    def ready(cursor):
        if not all(table_exists(cursor, t) for t in ('sheet_enquiries', 'sheet_enquiry_activities', 'sheet_enquiry_sync_runs')):
            raise HTTPException(503, 'Enquiry setup pending. Apply the web LMS 20261016_sheet_enquiries.sql migration.')

    def employees(cursor, user):
        condition = active_users(cursor)
        suffix, args = ('', []) if manager(user) else (' AND id=%s', [user['id']])
        cursor.execute(f'SELECT id,username,full_name FROM users WHERE {condition}{suffix} ORDER BY full_name', args)
        return list(cursor.fetchall())

    def assignee(cursor, row, payload, user):
        try:
            selected = int(payload.get('assigned_to') or row.get('assigned_to') or 0)
        except (TypeError, ValueError):
            raise HTTPException(422, 'Select an active employee.')
        if not manager(user) and selected != row.get('assigned_to'):
            raise HTTPException(403, 'Only administrators and managers may change assignment.')
        if selected not in [int(u['id']) for u in employees(cursor, user)]:
            raise HTTPException(422, 'Select an active employee.')
        if selected != row.get('assigned_to'):
            cursor.execute("UPDATE actions SET user_id=%s,assigned_to=%s WHERE entity_type='sheet_enquiry' AND entity_id=%s AND status IN ('Pending','Missed')", (selected, selected, row['id']))
            audit(cursor, row['id'], user, 'assignment', {'from': row.get('assigned_to'), 'to': selected})
        return selected

    def lead_permission(cursor, lead, user):
        if str(user.get('role', '')).strip().lower() == 'admin':
            return True
        if int(lead.get('created_by') or 0) == int(user['id']) or int(lead.get('assigned_to') or 0) == int(user['id']):
            return True
        if table_exists(cursor, 'lead_assignments'):
            cursor.execute('SELECT user_id FROM lead_assignments WHERE lead_id=%s ORDER BY assigned_at DESC LIMIT 1', (lead['id'],))
            last = cursor.fetchone()
            return bool(last and int(last['user_id']) == int(user['id']))
        return False

    def matches(cursor, phone):
        key = phone_key(phone)
        cursor.execute(f"SELECT id FROM leads WHERE COALESCE(is_deleted,0)<>1 AND LOWER(TRIM(lead_type)) IN ('buyer','tenant') AND {phone_expr()} IN (%s,%s,%s,%s)", (key, '91'+key, '0091'+key, '0'+key))
        return list(cursor.fetchall())

    def assign_repeats(c, conn, user):
        if not manager(user):
            return
        allowed = {int(u['id']) for u in employees(c, user)}
        c.execute("SELECT id,phone FROM sheet_enquiries WHERE assigned_to IS NULL AND main_lead_id IS NULL AND status<>'Invalid' ORDER BY id")
        candidates = list(c.fetchall())
        for candidate in candidates:
            key = phone_key(candidate.get('phone'))
            if len(key) != 10:
                continue
            variants = (key, '91'+key, '0091'+key, '0'+key)
            conn.begin()
            try:
                row = get_row(c, candidate['id'], user, True)
                if not row.get('assigned_to') and not row.get('main_lead_id') and row.get('status') != 'Invalid':
                    c.execute(f"SELECT (SELECT la.user_id FROM lead_assignments la WHERE la.lead_id=leads.id ORDER BY la.assigned_at DESC,la.user_id DESC LIMIT 1) assigned_to FROM leads WHERE COALESCE(is_deleted,0)<>1 AND LOWER(TRIM(lead_type)) IN ('buyer','tenant') AND {phone_expr()} IN (%s,%s,%s,%s) UNION ALL SELECT assigned_to FROM sheet_enquiries WHERE id<>%s AND status<>'Invalid' AND {phone_expr()} IN (%s,%s,%s,%s)", (*variants, row['id'], *variants))
                    owners = {int(r['assigned_to']) for r in c.fetchall() if r.get('assigned_to')}
                    if len(owners) == 1 and next(iter(owners)) in allowed:
                        owner = next(iter(owners))
                        c.execute('UPDATE sheet_enquiries SET assigned_to=%s,updated_at=NOW() WHERE id=%s', (owner, row['id']))
                        c.execute("UPDATE actions SET user_id=%s,assigned_to=%s WHERE entity_type='sheet_enquiry' AND entity_id=%s AND status IN ('Pending','Missed')", (owner, owner, row['id']))
                        audit(c, row['id'], user, 'assignment', {'from': None, 'to': owner, 'reason': 'repeat_phone_match'})
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    @router.get('/mobile/enquiry-management')
    def listing(q: str = Query('', max_length=255), status: str = '', assigned: str = '', due: bool = False,
                duplicates: bool = False, sort: str = 'newest', page: int = Query(1, ge=1), user: dict = Depends(authorized_user)):
        with get_db() as conn:
            c = conn.cursor(); ready(c)
            assign_repeats(c, conn, user)
            where, args = scope(user)
            unfiltered = not (q.strip() or status or assigned or due or duplicates)
            c.execute(f"""SELECT COUNT(*) total,COALESCE(SUM(e.status='New'),0) new_count,
             COALESCE(SUM(e.assigned_to IS NULL),0) unassigned,COALESCE(SUM(e.assigned_to IS NOT NULL),0) assigned,
             COALESCE(SUM(overdue.entity_id IS NOT NULL),0) due,COALESCE(SUM(e.status='Qualified'),0) qualified,
             COALESCE(SUM(e.main_lead_id IS NOT NULL),0) converted FROM sheet_enquiries e
             LEFT JOIN (SELECT DISTINCT entity_id FROM actions
              WHERE entity_type='sheet_enquiry' AND status IN ('Pending','Missed')
               AND TIMESTAMP(due_date,COALESCE(due_time,'00:00:00'))<=NOW()) overdue
              ON overdue.entity_id=e.id WHERE {where}""", args)
            stats = c.fetchone()
            if q.strip():
                where += ' AND (e.full_name LIKE %s OR e.phone LIKE %s OR e.email LIKE %s OR e.property_interest LIKE %s)'
                args += ['%' + q.strip() + '%'] * 4
            if status:
                if status not in STATUSES:
                    raise HTTPException(422, 'Choose a valid enquiry status.')
                where += ' AND e.status=%s'; args.append(status)
            if assigned == 'none':
                where += ' AND e.assigned_to IS NULL'
            elif assigned.isdigit():
                where += ' AND e.assigned_to=%s'; args.append(int(assigned))
            if due:
                where += ' AND ' + DUE
            duplicate = 'EXISTS (SELECT 1 FROM sheet_enquiries d WHERE d.phone=e.phone AND d.id<>e.id)'
            if duplicates:
                where += ' AND ' + duplicate
            order = {'newest': 'e.id DESC', 'oldest': 'e.id ASC', 'name': 'e.full_name ASC,e.id DESC', 'status': 'e.status ASC,e.id DESC'}.get(sort, 'e.id DESC')
            if unfiltered:
                total = stats['total']
            else:
                c.execute(f'SELECT COUNT(*) total FROM sheet_enquiries e WHERE {where}', args)
                total = c.fetchone()['total']
            pages = max(1, math.ceil(total / 27)); page = min(page, pages)
            c.execute(f'SELECT e.id,e.full_name,e.phone,e.property_interest,e.status,e.assigned_to,e.main_lead_id,e.imported_at,e.spreadsheet_id,e.worksheet,e.original_json,u.full_name employee,{duplicate} possible_duplicate FROM sheet_enquiries e LEFT JOIN users u ON u.id=e.assigned_to WHERE {where} ORDER BY {order} LIMIT 27 OFFSET %s', args + [(page-1)*27])
            items = []
            for row in c.fetchall():
                item = wire(row)
                # Cards only need the Q&A; source snapshots/raw import rows belong in detail.
                original = item.get('original') or {}
                item['original'] = {k: original.get(k, []) for k in ('questions', 'answers')}
                for key in ('current', 'qualification', 'source_changed'):
                    item.pop(key, None)
                items.append(item)
            # One query for the visible page, never one follow-up query per card.
            by_id = {int(item['id']): item for item in items}
            for item in items:
                item.update(next_followup=None, followup_count=0)
            if by_id:
                marks = ','.join(['%s'] * len(by_id))
                c.execute(f"""SELECT id,entity_id,due_date,due_time,status,description FROM actions
                 WHERE entity_type='sheet_enquiry' AND entity_id IN ({marks})
                 ORDER BY CASE WHEN status IN ('Pending','Missed') THEN 0 ELSE 1 END,
                  CASE WHEN status IN ('Pending','Missed') THEN due_date END ASC,
                  CASE WHEN status IN ('Pending','Missed') THEN due_time END ASC,id DESC""", list(by_id))
                for followup in c.fetchall():
                    item = by_id[int(followup['entity_id'])]
                    item['followup_count'] += 1
                    if item['next_followup'] is None:
                        item['next_followup'] = wire(followup)
            if by_id:
                c.execute(f"SELECT enquiry_id,details,created_at FROM sheet_enquiry_activities WHERE enquiry_id IN ({marks}) AND event_type='conversation' ORDER BY id DESC", list(by_id))
                for event in c.fetchall():
                    item = by_id[int(event['enquiry_id'])]
                    if 'last_conversation' not in item:
                        item['last_conversation'] = dict(unpack(event['details']), created_at=str(event['created_at']))
            return {'items': items, 'stats': stats, 'total': total, 'page': page, 'pages': pages,
                    'users': employees(c, user), 'can_assign': manager(user), 'can_convert': can_convert(user)}

    @router.get('/mobile/enquiry-management/sync-history')
    def sync_history(user: dict = Depends(authorized_user)):
        if str(user.get('role', '')).strip().lower() != 'admin':
            raise HTTPException(403, 'Administrator access required.')
        with get_db() as conn:
            c = conn.cursor(); ready(c)
            c.execute('SELECT * FROM sheet_enquiry_sync_runs ORDER BY id DESC LIMIT 20')
            return [wire(r) for r in c.fetchall()]

    @router.get('/mobile/enquiry-management/{enquiry_id}')
    def detail(enquiry_id: int, user: dict = Depends(authorized_user)):
        with get_db() as conn:
            c = conn.cursor(); ready(c); row = get_row(c, enquiry_id, user)
            c.execute('SELECT a.*,u.full_name actor FROM sheet_enquiry_activities a LEFT JOIN users u ON u.id=a.actor_id WHERE enquiry_id=%s ORDER BY a.id DESC', (enquiry_id,))
            history = [wire(r) for r in c.fetchall()]
            c.execute("SELECT id,title,description,status,due_date,due_time FROM actions WHERE entity_type='sheet_enquiry' AND entity_id=%s ORDER BY due_date DESC,due_time DESC", (enquiry_id,))
            followups = [wire(r) for r in c.fetchall()]
            where, args = scope(user)
            c.execute(f'SELECT e.id,e.property_interest FROM sheet_enquiries e WHERE {where} AND e.phone=%s AND e.id<>%s ORDER BY e.id DESC LIMIT 20', args + [row['phone'], enquiry_id])
            repeats = list(c.fetchall())
            return {'item': wire(row), 'history': history, 'followups': followups, 'duplicates': repeats,
                    'matching_lead_count': len(matches(c, row['phone'])), 'users': employees(c, user),
                    'can_assign': manager(user), 'can_convert': can_convert(user)}

    @router.get('/mobile/enquiry-management/{enquiry_id}/leads')
    def search_leads(enquiry_id: int, q: str = Query('', max_length=100), user: dict = Depends(authorized_user)):
        with get_db() as conn:
            c = conn.cursor(); ready(c); get_row(c, enquiry_id, user)
            if len(q.strip()) < 2:
                return []
            term = '%' + q.strip().replace('!', '!!').replace('%', '!%').replace('_', '!_') + '%'
            search = "name LIKE %s ESCAPE '!'"; args = [term]
            if re.fullmatch(r'[+0-9() .\s-]+', q.strip()):
                key = phone_key(q)
                if len(key) >= 2:
                    search += f' OR {phone_expr()} LIKE %s'; args.append('%'+key+'%')
            c.execute(f"SELECT leads.*,(SELECT la.user_id FROM lead_assignments la WHERE la.lead_id=leads.id ORDER BY la.assigned_at DESC,la.user_id DESC LIMIT 1) current_owner FROM leads WHERE COALESCE(is_deleted,0)<>1 AND LOWER(TRIM(lead_type)) IN ('buyer','tenant') AND ({search}) ORDER BY name,id LIMIT 100", args)
            rows = list(c.fetchall())
            return [dict({k: r.get(k) for k in ('id', 'name', 'phone', 'lead_type', 'location')}, assigned_to=r.get('current_owner') or r.get('assigned_to'))
                    for r in rows if lead_permission(c, r, user)][:20]

    @router.post('/mobile/enquiry-management/{enquiry_id}/{action}')
    def update(enquiry_id: int, action: str, payload: dict = Body(...), user: dict = Depends(authorized_user)):
        if action not in ('assign', 'mark_invalid', 'restore_invalid', 'followup', 'qualify', 'link_existing'):
            raise HTTPException(422, 'Unknown enquiry action.')
        if action == 'qualify' and not can_convert(user):
            raise HTTPException(403, 'Only administrators and senior agents may convert to Main Leads.')
        if action == 'assign' and not manager(user):
            raise HTTPException(403, 'Only administrators and managers may assign enquiries.')
        with get_db() as conn:
            c = conn.cursor(); ready(c)
            locked = False
            try:
                if action == 'qualify':
                    c.execute("SELECT GET_LOCK('sheet-enquiry-conversion',10) acquired")
                    locked = bool(c.fetchone()['acquired'])
                    if not locked:
                        raise HTTPException(409, 'Another conversion is in progress. Please retry.')
                conn.begin()
                row = get_row(c, enquiry_id, user, True)
                if row.get('main_lead_id'):
                    # Retried conversion is idempotent, every other edit is rejected.
                    if action == 'qualify' or (action == 'link_existing' and str(payload.get('lead_id')) == str(row['main_lead_id'])):
                        conn.commit(); return {'lead_id': row['main_lead_id'], 'already_converted': True}
                    raise HTTPException(409, 'Converted enquiries are read-only.')
                if action == 'assign':
                    owner = assignee(c, row, payload, user)
                    c.execute('UPDATE sheet_enquiries SET assigned_to=%s,updated_at=NOW() WHERE id=%s', (owner, enquiry_id))
                elif action in ('mark_invalid', 'restore_invalid'):
                    if action == 'restore_invalid' and row['status'] != 'Invalid':
                        raise HTTPException(409, 'Only invalid enquiries can be restored.')
                    status = 'Invalid' if action == 'mark_invalid' else 'New'
                    c.execute('UPDATE sheet_enquiries SET status=%s,updated_at=NOW() WHERE id=%s', (status, enquiry_id))
                    audit(c, enquiry_id, user, 'status', {'from': row['status'], 'to': status})
                elif action == 'followup':
                    owner = row.get('assigned_to')
                    due = future_due(payload.get('due_at')) if payload.get('due_at') else None
                    outcome = payload.get('outcome')
                    if outcome not in OUTCOMES:
                        raise HTTPException(422, 'Choose a follow-up outcome.')
                    remarks = str(payload.get('remarks') or '').strip()
                    if len(remarks.encode()) > 2000:
                        raise HTTPException(422, 'Remarks must be 2000 bytes or fewer.')
                    if not owner:
                        owner = assignee(c, row, payload, user)
                        c.execute('UPDATE sheet_enquiries SET assigned_to=%s,updated_at=NOW() WHERE id=%s', (owner, enquiry_id))
                    action_id = None
                    if due:
                        c.execute("""INSERT INTO actions (user_id,assigned_to,lead_id,entity_type,entity_id,title,description,action_type,priority,due_date,due_time,status)
                         VALUES (%s,%s,NULL,'sheet_enquiry',%s,%s,%s,'Call','Medium',%s,%s,'Pending')""",
                         (owner, owner, enquiry_id, f"Enquiry {row.get('full_name') or ''} #{enquiry_id} follow-up", 'Outcome: '+outcome+'\n'+remarks, due.date(), due.strftime('%H:%M:%S')))
                        action_id = c.lastrowid
                    if outcome == 'Connected':
                        c.execute('UPDATE sheet_enquiries SET contacted_at=COALESCE(contacted_at,NOW()),updated_at=NOW() WHERE id=%s', (enquiry_id,))
                    audit(c, enquiry_id, user, 'followup' if due else 'conversation', {'action_id': action_id, 'due_at': payload.get('due_at') or None, 'outcome': outcome, 'remarks': remarks})
                else:
                    owner = assignee(c, row, payload, user)
                    if action == 'link_existing':
                        try:
                            lead_id = int(payload.get('lead_id') or 0)
                        except (TypeError, ValueError):
                            raise HTTPException(422, 'Select an existing lead.')
                        c.execute("SELECT * FROM leads WHERE id=%s AND COALESCE(is_deleted,0)<>1 AND LOWER(TRIM(lead_type)) IN ('buyer','tenant') FOR UPDATE", (lead_id,))
                        lead = c.fetchone()
                        if not lead or not lead_permission(c, lead, user):
                            raise HTTPException(403, 'Choose a Buyer or Tenant lead you have permission to modify.')
                        audit(c, enquiry_id, user, 'linked_existing', {'lead_id': lead_id, 'assigned_to': owner, 'from_status': row['status'], 'to_status': 'Qualified', 'phone_differs': phone_key(lead.get('phone')) != phone_key(row['phone'])})
                    else:
                        q = qualification(payload)
                        if matches(c, q['phone']):
                            raise HTTPException(409, 'A matching Main Lead exists. Use Link existing lead to avoid creating a duplicate.')
                        # Respect the web repository's cross-table buyer/tenant duplicate rule.
                        if table_exists(c, 'telecaller_leads'):
                            key = phone_key(q['phone'])
                            c.execute(f"SELECT id FROM telecaller_leads WHERE COALESCE(is_deleted,0)<>1 AND LOWER(TRIM(lead_type)) IN ('buyer','tenant') AND {phone_expr()} IN (%s,%s,%s,%s) LIMIT 1", (key, '91'+key, '0091'+key, '0'+key))
                            if c.fetchone():
                                raise HTTPException(409, 'A matching Telecaller Lead exists. Resolve it in the LMS before conversion.')
                        data = {k: v for k, v in q.items() if v and k != 'budget'}
                        data.update(email=row.get('email'), source_type='Inventory', created_by=user['id'], assigned_to=owner,
                                    lead_status=q['lead_status'] or 'Warm', created_at=datetime.now(ZoneInfo('Asia/Kolkata')).replace(tzinfo=None),
                                    meta_enquiry_text=f"{wire(row)['source']} enquiry #{enquiry_id}\nProperty: {row['property_interest']}\nEmail: {row.get('email', '')}\nQualification: {json.dumps(q, ensure_ascii=False)}\nOriginal questions and answers: {row['original_json']}")
                        available = columns(c, 'leads')
                        if 'meta_enquiry_text' not in available:
                            raise HTTPException(503, 'Apply the web LMS 20261017_meta_enquiry_text.sql migration before conversion.')
                        data = {k: v for k, v in data.items() if k in available}
                        fields = list(data)
                        c.execute('INSERT INTO leads ('+','.join('`'+k+'`' for k in fields)+') VALUES ('+','.join(['%s']*len(fields))+')', [data[k] for k in fields])
                        lead_id = c.lastrowid
                        c.execute('INSERT INTO lead_assignments (lead_id,user_id,assigned_by) VALUES (%s,%s,%s)', (lead_id, owner, user['id']))
                        c.execute('UPDATE sheet_enquiries SET qualification_json=%s WHERE id=%s', (json.dumps(q, ensure_ascii=False), enquiry_id))
                        audit(c, enquiry_id, user, 'qualification', {'from': row['status'], 'to': 'Qualified', 'qualification': q})
                        audit(c, enquiry_id, user, 'converted', {'lead_id': lead_id, 'linked_existing': False})
                    c.execute("UPDATE sheet_enquiries SET assigned_to=%s,status='Qualified',main_lead_id=%s,converted_at=NOW(),updated_at=NOW() WHERE id=%s", (owner, lead_id, enquiry_id))
                    conn.commit(); return {'lead_id': lead_id}
                conn.commit(); return {'message': 'Enquiry updated.'}
            except Exception:
                conn.rollback(); raise
            finally:
                if locked:
                    c.execute("SELECT RELEASE_LOCK('sheet-enquiry-conversion')")
