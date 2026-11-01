"""Global search over mobile screen readers, after their scope and privacy rules."""
import inspect
import logging
import re
from fastapi import Depends, HTTPException, Query

FIELDS = ('id','name','full_name','builder_name','company_name','phone','phone_2','email',
          'address','location','owner_name','property_interest','property_type','floor','bhk',
          'area_size','month_year','page_no','remarks','details','first_name','middle_name','last_name','notes','note','configuration','book_month','category','lead_status','status')
PHONE = {'phone', 'phone_2'}


def matches(row, term, exact=False):
    digits = re.sub(r'\D', '', term)
    phone_term = bool(digits and re.fullmatch(r'[+\d\s().-]+', term))
    for field in FIELDS:
        if field == 'id' or row.get(field) is None:
            continue
        value = str(row[field]).strip().casefold()
        if (value == term.casefold()) if exact else (term.casefold() in value):
            return True
        if field in PHONE and phone_term:
            number = re.sub(r'\D', '', value)
            if (number == digits) if exact else (digits in number):
                return True
    return False


def register_routes(router, env):
    def route_reader(path, user, page):
        endpoint = next(r.endpoint for r in router.routes if r.path.endswith(path) and 'GET' in r.methods)
        args = {}
        for name, param in inspect.signature(endpoint).parameters.items():
            default = param.default
            args[name] = getattr(default, 'default', default)
        args.update(page=page, user=user)
        return endpoint(**args)

    def pages(reader, user, **extra):
        offset = 0
        while True:
            result = reader(current_user=user, skip=offset, limit=200, **extra)
            rows = result.get('items', []) if isinstance(result, dict) else result
            for row in rows:
                yield row.model_dump() if hasattr(row, 'model_dump') else row.dict() if hasattr(row, 'dict') else row
            if len(rows) < 200:
                break
            offset += 200

    def route_pages(path, user):
        page = 1
        while True:
            result = route_reader(path, user, page)
            yield from result['items']
            if not result.get('has_more', page < result.get('pages', 1)):
                break
            page += 1

    def extra_rows(kind, user):
        # Fixed queries only; record scope mirrors the corresponding web source.
        queries = {
            'contacts': ("SELECT * FROM attached_contacts WHERE owner_id=%s AND COALESCE(is_deleted,0)<>1 ORDER BY id", [user['id']]),
            'ocr': ("SELECT r.*,p.month_year,p.page_no FROM inventory_records r JOIN inventory_pages p ON p.id=r.page_id WHERE COALESCE(r.is_deleted,0)=0 ORDER BY r.id", []),
            'cold': ("SELECT l.* FROM leads l WHERE COALESCE(l.is_deleted,0)<>1 AND LOWER(TRIM(l.source_type))='cold_calling' AND LOWER(COALESCE(l.lead_status,''))<>'sold' AND NOT (LOWER(COALESCE(l.lead_status,'')) REGEXP '(^|,)[[:space:]]*un-?available[[:space:]]*(,|$)') ORDER BY l.id", []),
            'agent': ("SELECT l.* FROM leads l JOIN builders b ON b.id=l.builder_id WHERE l.is_deleted<>1 AND LOWER(l.lead_type)='agent' AND b.record_category IN ('Agent','Builder cum Agent') AND LOWER(COALESCE(l.lead_status,'')) NOT IN ('sold','closed/lost','already rented') AND NOT (LOWER(COALESCE(l.lead_status,'')) REGEXP '(^|,)[[:space:]]*un-?available[[:space:]]*(,|$)') ORDER BY l.id", []),
        }
        sql, args = queries[kind]
        offset = 0
        while True:
            with env['get_db']() as conn:
                cursor = conn.cursor()
                cursor.execute(sql + ' LIMIT 200 OFFSET %s', args + [offset])
                rows = list(cursor.fetchall())
                if kind in ('cold', 'agent'):
                    env['attach_current_assignees'](cursor, rows)
                    rows = env['apply_lead_masking_batch'](cursor, rows, user)
            yield from rows
            if len(rows) < 200:
                break
            offset += 200

    @router.get('/global-search')
    def search(q: str = Query('', max_length=200), exact: bool = False,
               page: int = Query(1, ge=1), source: str = '', sources_only: bool = False,
               current_user: dict = Depends(env['get_current_user'])):
        if not current_user.get('id') or current_user.get('username') != 'vsawariya':
            raise HTTPException(403, 'Global search is available only to vsawariya.')
        term = q.strip()
        if len(term) < 2:
            return {'groups': {}, 'errors': []}
        with env['get_db']() as conn:
            flags = env['get_user_mobile_feature_flag_values'](conn.cursor(), current_user['id'])
        sources = {
            'contacts': ('My Contacts', 'contacts', lambda: extra_rows('contacts', current_user), ''),
            'cold': ('Cold Calling Inventory', 'cold_calling_inventory', lambda: extra_rows('cold', current_user), '/leads/'),
            'agent': ('Agent Inventory', 'agent_inventory', lambda: extra_rows('agent', current_user), '/leads/'),
            'clients': ('Clients', 'buyer_leads', lambda: pages(env['get_client_leads'], current_user), '/leads/'),
            'inventory': ('Inventory', 'seller_inventory', lambda: pages(env['get_inventory_leads'], current_user), '/leads/'),
            'assigned': ('Assigned Leads', 'assigned_leads', lambda: pages(env['get_mobile_assigned_leads'], current_user), '/leads/'),
            'builders': ('Builders & Agents', 'builders_agents', lambda: pages(env['get_builders'], current_user), '/builders/'),
            'kothis': ('Kothi Inventory', 'legacy_inventory', lambda: pages(env['get_mobile_enquiries'], current_user, category='kothi'), '/legacy-inventory'),
            'legacy': ('Legacy Inventory', 'legacy_inventory', lambda: pages(env['get_mobile_enquiries'], current_user, category='floor'), '/legacy-inventory'),
            'enquiries': ('Advertisement Enquiries', 'enquiry_management', lambda: route_pages('/mobile/enquiry-management', current_user), '/enquiries/'),
            'monthly': ('Monthly Inventory', None, lambda: route_pages('/monthly-inventory', current_user), '/monthly-inventory'),
        }
        if str(current_user.get('role', '')).strip().lower() in ('admin', 'manager'):
            sources['ocr'] = ('Inventory OCR', 'inventory_ocr', lambda: extra_rows('ocr', current_user), '')
        if source and source not in sources:
            raise HTTPException(422, 'Unknown search source.')
        if sources_only:
            return {'sources': [{'key': key, 'label': label}
                    for key, (label, flag, _, _) in sources.items()
                    if not flag or flags.get(flag, False)]}
        groups, errors = {}, []
        for key, (label, flag, reader, path) in sources.items():
            if source and source != key or flag and not flags.get(flag, False):
                continue
            try:
                total, items = 0, []
                for row in reader():
                    if row.get('can_view_sensitive') is False:
                        row = {k: v for k, v in row.items() if k in ('id','name','lead_status','location','address','phone','property_type','floor','bhk','area_size','budget','price')}
                    if not matches(row, term, exact):
                        continue
                    total += 1
                    if (page - 1)*20 < total <= page*20:
                        items.append({'row': {k: row[k] for k in FIELDS if k in row},
                                      'url': path + str(row['id']) if path.endswith('/') else (path + '?entry_id=' + str(row['id']) if key == 'monthly' else path)})
                groups[key] = {'label': label, 'total': total, 'items': items}
            except Exception:
                logging.exception('Global search source %s failed', key)
                errors.append(label)
        return {'groups': groups, 'errors': errors}
