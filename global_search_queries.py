"""Lightweight search candidates; privacy is still applied before final matching.

Never call screen listing endpoints here: their counts, scoring, followups and
assignment maintenance turn a search into repeated full database scans.
"""
import re


def candidate_clause(columns, term, exact=False, alias='s'):
    """SQL superset of matching, with literal LIKE characters and phone formatting.

    Final matching happens on the masked record, so a private field cannot cause
    a result or count to be exposed. Phone digit subsequences intentionally admit
    false positives in exchange for compatibility with arbitrary punctuation.
    """
    clauses, args = [], []
    escaped = term.lower().replace('!', '!!').replace('%', '!%').replace('_', '!_')
    for column in columns:
        if column == 'id':
            continue
        expr = f"LOWER(TRIM(CAST({alias}.`{column}` AS CHAR)))"
        clauses.append(f"{expr} LIKE %s ESCAPE '!'" )
        args.append(escaped if exact else '%' + escaped + '%')
        if column == 'address' and re.fullmatch(r'[A-Za-z]+[\s\-‐‑‒–—−]*\d+[A-Za-z]?', term):
            canonical = expr
            for character in (' ', '-', '‐', '‑', '‒', '–', '—', '−', '\t', '\n', '\r'):
                canonical = f"REPLACE({canonical}, %s, '')"
                args.append(character)
            clauses.append(f"{canonical} LIKE %s ESCAPE '!'" )
            normalized = re.sub(r'[\s\-‐‑‒–—−]', '', term.lower())
            args.append(normalized if exact else '%' + normalized + '%')
        if column in ('phone', 'phone_2') and re.fullmatch(r'[+\d\s().-]+', term):
            digits = re.sub(r'\D', '', term)
            if digits:
                clauses.append(f"CAST({alias}.`{column}` AS CHAR) LIKE %s")
                args.append('%' + '%'.join(digits) + '%')
    return '(' + ' OR '.join(clauses or ['0=1']) + ')', args


def rows(env, kind, user, term, exact, fields):
    """Read only SQL candidates in stable ID batches, then use source masking."""
    with env['get_db']() as conn:
        cursor = conn.cursor()
        columns = lambda table: env['_table_columns'](cursor, table)
        lead_source = kind in ('clients', 'inventory', 'assigned', 'cold', 'agent')
        args = []
        if lead_source:
            available = columns('leads')
            base, where = 'SELECT l.* FROM leads l', ['COALESCE(l.is_deleted,0)=0']
            if kind == 'clients':
                where.append("l.lead_type IN ('buyer','tenant')")
            elif kind == 'inventory':
                where.append("l.lead_type IN ('seller','owner','landlord','builder','agent')")
            elif kind == 'cold':
                where = ['COALESCE(l.is_deleted,0)<>1']
                where += ["LOWER(TRIM(l.source_type))='cold_calling'", "LOWER(COALESCE(l.lead_status,''))<>'sold'", "NOT (LOWER(COALESCE(l.lead_status,'')) REGEXP '(^|,)[[:space:]]*un-?available[[:space:]]*(,|$)')"]
            elif kind == 'agent':
                where = ['l.is_deleted<>1']
                base += ' JOIN builders b ON b.id=l.builder_id'
                where += ["LOWER(l.lead_type)='agent'", "b.record_category IN ('Agent','Builder cum Agent')", "LOWER(COALESCE(l.lead_status,'')) NOT IN ('sold','closed/lost','already rented')", "NOT (LOWER(COALESCE(l.lead_status,'')) REGEXP '(^|,)[[:space:]]*un-?available[[:space:]]*(,|$)')"]
            else:
                assignment = columns('lead_assignments')
                membership = []
                admin = str(user.get('role') or '').strip().lower() == 'admin'
                if 'assigned_to' in available:
                    membership.append('NULLIF(l.assigned_to,0) IS NOT NULL' if admin else 'l.assigned_to=%s')
                    if not admin: args.append(user['id'])
                if {'lead_id', 'user_id'}.issubset(assignment):
                    if admin:
                        order = ','.join(f'la.{c} DESC' for c in ('assigned_at','id','user_id') if c in assignment)
                        membership.append(f'(SELECT la.user_id FROM lead_assignments la WHERE la.lead_id=l.id ORDER BY {order} LIMIT 1) IS NOT NULL')
                    else:
                        membership.append('EXISTS (SELECT 1 FROM lead_assignments mine WHERE mine.lead_id=l.id AND mine.user_id=%s)')
                        args.append(user['id'])
                where.append('(' + ' OR '.join(membership or ['0=1']) + ')')
        elif kind in ('legacy', 'kothis'):
            source = 'floor' if kind == 'legacy' else 'kothi'
            base = env[f'_legacy_{source}_select']()
            where = [env[f'_legacy_{source}_where']()]
            available = {'id','name','phone','location','address','bhk','floor','area_size','property_type','status','notes'}
        elif kind == 'monthly':
            base = 'SELECT e.*,b.book_month,b.category FROM monthly_inventory_entries e JOIN monthly_inventory_books b ON b.id=e.book_id'
            where = ['e.is_deleted=0']
            available = columns('monthly_inventory_entries') | {'book_month','category'}
        elif kind == 'enquiries':
            base = 'SELECT e.* FROM sheet_enquiries e'
            # Same read scope as enquiry_management.scope; no listing side effects.
            manager = str(user.get('role') or '').strip().lower() in ('admin', 'manager')
            condition, args = ('1=1', []) if manager else ('e.assigned_to=%s', [user['id']])
            where, available = [condition], columns('sheet_enquiries')
        elif kind == 'ocr':
            base = 'SELECT r.*,p.month_year,p.page_no FROM inventory_records r JOIN inventory_pages p ON p.id=r.page_id'
            where = ['COALESCE(r.is_deleted,0)=0']
            available = columns('inventory_records') | {'month_year','page_no'}
        elif kind == 'contacts':
            base = 'SELECT c.* FROM attached_contacts c'
            where, args = ['c.owner_id=%s', 'COALESCE(c.is_deleted,0)<>1'], [user['id']]
            available = columns('attached_contacts')
        elif kind == 'builders':
            base, where, available = 'SELECT b.* FROM builders b', ['1=1'], columns('builders')
        else:
            raise ValueError('Unknown source')
        predicate, search_args = candidate_clause([f for f in fields if f in available], term, exact)
        query = '(' + base + ' WHERE ' + ' AND '.join(where) + ') s'
        last_id = 0
        while True:
            cursor.execute('SELECT s.* FROM ' + query + ' WHERE s.id>%s AND ' + predicate + ' ORDER BY s.id LIMIT 200', args + [last_id] + search_args)
            batch = list(cursor.fetchall())
            if not batch:
                break
            fetched_count = len(batch)
            last_id = batch[-1]['id']
            if lead_source:
                env['attach_current_assignees'](cursor, batch)
                if kind == 'assigned':
                    batch = [env['_lead_summary'](row, str(user.get('role') or '').strip().lower(), user['id']) for row in batch]
                else:
                    batch = env['apply_lead_masking_batch'](cursor, batch, user)
            elif kind in ('legacy','kothis'):
                batch = env['_normalize_legacy_inventory_rows'](batch, user.get('role',''), user['id'])
            yield from batch
            if fetched_count < 200:
                break
