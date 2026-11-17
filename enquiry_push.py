"""Expo push delivery for newly saved enquiries, independent of phone app state."""
import asyncio
import json
import logging
import os
import re
from urllib.request import Request, urlopen
from fastapi import Body, Depends, HTTPException

TOKEN = re.compile(r'^(?:ExponentPushToken|ExpoPushToken)\[[A-Za-z0-9_-]+\]$')


def ensure_devices(cursor):
    cursor.execute('''CREATE TABLE IF NOT EXISTS mobile_enquiry_push_devices (
        token VARCHAR(255) NOT NULL PRIMARY KEY, user_id INT NOT NULL,
        last_enquiry_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        KEY user_devices (user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')


def expo_send(messages):
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    if os.getenv('EXPO_ACCESS_TOKEN'):
        headers['Authorization'] = 'Bearer ' + os.environ['EXPO_ACCESS_TOKEN']
    request = Request('https://exp.host/--/api/v2/push/send', data=json.dumps(messages).encode(), headers=headers, method='POST')
    with urlopen(request, timeout=10) as response:
        data = json.load(response)
    if data.get('errors') or not isinstance(data.get('data'), list) or len(data['data']) != len(messages):
        raise RuntimeError('Expo did not acknowledge all notifications')
    return data['data']


def dispatch(get_db, send=expo_send):
    from enquiry_management import scope, wire
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT GET_LOCK('mobile_enquiry_push_delivery',0) acquired")
        if not c.fetchone()['acquired']:
            return
        try:
            c.execute('SELECT d.token,d.user_id,d.last_enquiry_id,u.role FROM mobile_enquiry_push_devices d JOIN users u ON u.id=d.user_id ORDER BY d.updated_at DESC LIMIT 500')
            devices = list(c.fetchall())
            c.execute('SELECT COALESCE(MAX(id),0) id FROM sheet_enquiries')
            maximum = int(c.fetchone()['id'])
            c.execute("SHOW TABLES LIKE 'user_mobile_feature_flags'")
            has_flags = bool(c.fetchone())
            for device in devices:
                if has_flags:
                    c.execute("SELECT feature_key,is_enabled FROM user_mobile_feature_flags WHERE user_id=%s AND feature_key IN ('enquiry_management','__default__')", (device['user_id'],))
                flags = {r['feature_key']: bool(r['is_enabled']) for r in c.fetchall()} if has_flags else {}
                if not flags.get('enquiry_management', flags.get('__default__', True)):
                    continue
                where, args = scope({'id':device['user_id'], 'role':device['role']})
                c.execute(f'SELECT e.* FROM sheet_enquiries e WHERE {where} AND e.id>%s AND e.id<=%s ORDER BY e.id LIMIT 10', args + [device['last_enquiry_id'], maximum])
                rows = list(c.fetchall())
                if not rows:
                    c.execute('UPDATE mobile_enquiry_push_devices SET last_enquiry_id=%s WHERE token=%s AND user_id=%s', (maximum, device['token'], device['user_id']))
                    conn.commit()
                    continue
                messages = [{'to':device['token'], 'title':'New ' + wire(row).get('source','') + ' enquiry',
                             'body':'A new enquiry is ready to review.', 'sound':'default',
                             'data':{'type':'enquiry','enquiryId':int(row['id'])}} for row in rows]
                try:
                    tickets = send(messages)
                    cursor = int(device['last_enquiry_id'])
                    for row, ticket in zip(rows, tickets):
                        if ticket.get('status') != 'ok':
                            if ticket.get('details',{}).get('error') == 'DeviceNotRegistered':
                                c.execute('DELETE FROM mobile_enquiry_push_devices WHERE token=%s', (device['token'],))
                            break
                        cursor = int(row['id'])
                    c.execute('UPDATE mobile_enquiry_push_devices SET last_enquiry_id=%s WHERE token=%s AND user_id=%s', (cursor,device['token'],device['user_id']))
                    conn.commit()
                except Exception:
                    conn.rollback()
                    logging.warning('Enquiry push delivery failed; will retry (no payload logged)')
        finally:
            c.execute("SELECT RELEASE_LOCK('mobile_enquiry_push_delivery')")


def register_push_routes(router, get_db, authorized_user, ready):
    @router.post('/mobile/enquiry-push-device')
    def register(payload: dict = Body(...), user: dict = Depends(authorized_user)):
        token = payload.get('token')
        if not isinstance(token,str) or len(token)>255 or not TOKEN.fullmatch(token):
            raise HTTPException(422,'Provide a valid Expo push token.')
        with get_db() as conn:
            c=conn.cursor(); ready(c); ensure_devices(c)
            c.execute('SELECT COALESCE(MAX(id),0) id FROM sheet_enquiries')
            maximum=int(c.fetchone()['id'])
            # Refreshing the same account preserves pending delivery; account changes start fresh.
            c.execute('''INSERT INTO mobile_enquiry_push_devices (token,user_id,last_enquiry_id) VALUES (%s,%s,%s)
                ON DUPLICATE KEY UPDATE last_enquiry_id=IF(user_id=VALUES(user_id),last_enquiry_id,VALUES(last_enquiry_id)),user_id=VALUES(user_id),updated_at=NOW()''', (token,user['id'],maximum))
            conn.commit()
        return {'success':True}

    @router.delete('/mobile/enquiry-push-device')
    def unregister(payload: dict = Body(...), user: dict = Depends(authorized_user)):
        if not isinstance(payload.get('token'),str) or not TOKEN.fullmatch(payload['token']):
            raise HTTPException(422,'Provide a valid Expo push token.')
        with get_db() as conn:
            c=conn.cursor(); ensure_devices(c)
            c.execute('DELETE FROM mobile_enquiry_push_devices WHERE token=%s AND user_id=%s',(payload.get('token',''),user['id']))
            conn.commit()
        return {'success':True}

    task = None

    async def worker():
        while True:
            try:
                await asyncio.to_thread(dispatch,get_db)
            except asyncio.CancelledError:
                raise
            except Exception:
                logging.warning('Enquiry push worker unavailable; retrying after setup')
            await asyncio.sleep(15)

    @router.on_event('startup')
    async def start():
        nonlocal task
        if os.getenv('ENQUIRY_PUSH_ENABLED','1') == '1':
            try:
                with get_db() as conn:
                    c=conn.cursor(); ready(c); ensure_devices(c); conn.commit()
            except Exception:
                logging.warning('Enquiry push setup pending; device registration will retry setup')
            task=asyncio.create_task(worker())

    @router.on_event('shutdown')
    async def stop():
        if task:
            task.cancel()
            try: await task
            except asyncio.CancelledError: pass
