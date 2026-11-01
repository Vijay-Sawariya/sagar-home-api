"""Global search over mobile screen readers, after their scope and privacy rules."""
from contextlib import contextmanager
from time import monotonic
import logging
import re
from global_search_queries import rows as search_rows
from fastapi import Depends, HTTPException, Query

FIELDS = ('id','name','full_name','builder_name','company_name','phone','phone_2','email',
          'address','location','owner_name','property_interest','property_type','floor','bhk',
          'area_size','month_year','page_no','remarks','details','first_name','middle_name','last_name','notes','note','configuration','book_month','category','lead_status','status')
PHONE = {'phone', 'phone_2'}


def matches(row, term, exact=False):
    digits = re.sub(r'\D', '', term)
    phone_term = bool(digits and re.fullmatch(r'[+\d\s().-]+', term))
    address_term = bool(re.fullmatch(r'[a-zA-Z]+[\s\-‐‑‒–—−]*\d+[a-zA-Z]?', term))
    compact_term = re.sub(r'[\s\-‐‑‒–—−]', '', term.casefold())
    for field in FIELDS:
        if field == 'id' or row.get(field) is None:
            continue
        value = str(row[field]).strip().casefold()
        if (value == term.casefold()) if exact else (term.casefold() in value):
            return True
        if field == 'address' and address_term:
            compact = re.sub(r'[\s\-‐‑‒–—−]', '', value)
            if (compact == compact_term) if exact else (compact_term in compact):
                return True
        if field in PHONE and phone_term:
            number = re.sub(r'\D', '', value)
            if (number == digits) if exact else (digits in number):
                return True
    return False


def register_routes(router, env):
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
            'contacts': ('My Contacts', 'contacts', None, ''),
            'cold': ('Cold Calling Inventory', 'cold_calling_inventory', None, '/leads/'),
            'agent': ('Agent Inventory', 'agent_inventory', None, '/leads/'),
            'clients': ('Clients', 'buyer_leads', None, '/leads/'),
            'inventory': ('Inventory', 'seller_inventory', None, '/leads/'),
            'assigned': ('Assigned Leads', 'assigned_leads', None, '/leads/'),
            'builders': ('Builders & Agents', 'builders_agents', None, '/builders/'),
            'kothis': ('Kothi Inventory', 'legacy_inventory', None, '/legacy-inventory'),
            'legacy': ('Legacy Inventory', 'legacy_inventory', None, '/legacy-inventory'),
            'enquiries': ('Advertisement Enquiries', 'enquiry_management', None, '/enquiries/'),
            'monthly': ('Monthly Inventory', None, None, '/monthly-inventory'),
        }
        if str(current_user.get('role', '')).strip().lower() in ('admin', 'manager'):
            sources['ocr'] = ('Inventory OCR', 'inventory_ocr', None, '')
        if source and source not in sources:
            raise HTTPException(422, 'Unknown search source.')
        if sources_only:
            return {'sources': [{'key': key, 'label': label}
                    for key, (label, flag, _, _) in sources.items()
                    if not flag or flags.get(flag, False)]}
        groups, errors, timings = {}, [], {}
        # A search is one unit of work. Reuse its connection and schema metadata;
        # opening a remote MySQL connection for every source adds network latency.
        with env['get_db']() as connection:
            @contextmanager
            def search_db():
                yield connection
            columns_cache = {}
            def search_columns(cursor, table):
                if table not in columns_cache:
                    columns_cache[table] = env['_table_columns'](cursor, table)
                return columns_cache[table]
            search_env = {**env, 'get_db': search_db, '_table_columns': search_columns}
            for key, (label, flag, reader, path) in sources.items():
                if source and source != key or flag and not flags.get(flag, False):
                    continue
                started = monotonic()
                try:
                    total, items = 0, []
                    for row in search_rows(search_env, key, current_user, term, exact, FIELDS):
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
                finally:
                    timings[key] = round((monotonic() - started) * 1000)
                    logging.info('Global search source=%s elapsed_ms=%s', key, timings[key])
        return {'groups': groups, 'errors': errors, 'timings_ms': timings}
