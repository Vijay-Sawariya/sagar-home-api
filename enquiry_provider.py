"""Safe, compact presentation fields from the latest enquiry snapshot."""
import json
from urllib.parse import urlsplit


def text(value):
    return str(value).strip() if isinstance(value, (str, int, float)) and not isinstance(value, bool) else ''


def details(payload):
    payload = payload if isinstance(payload, dict) else {}
    provider = payload.get('provider_fields') if isinstance(payload.get('provider_fields'), dict) else {}
    lead = payload.get('parsed_lead') if isinstance(payload.get('parsed_lead'), dict) else {}
    result = {key: text(provider.get(key)) for key in ('listing_id', 'response_id', 'location', 'configuration', 'budget')}
    result['location'] = result['location'] or text(lead.get('location'))
    result['configuration'] = result['configuration'] or text(lead.get('bhk'))
    result['budget'] = result['budget'] or (' '.join((text(lead.get('budget_max')), text(lead.get('unit')))).strip())
    result['message'] = next((text(value) for value in (provider.get('message'), provider.get('complete_message'), payload.get('message'), lead.get('meta_enquiry_text')) if text(value)), '')
    # An explicit empty provider URL means the link was removed.
    candidate = text(provider.get('listing_URL', lead.get('listing_URL', payload.get('listing_URL', ''))))
    try:
        parts = urlsplit(candidate)
        result['listing_url'] = candidate if parts.scheme.lower() in ('http', 'https') and parts.hostname and parts.username is None and parts.password is None else ''
    except ValueError:
        result['listing_url'] = ''
    return result


def latest_snapshot(row):
    for key in ('current_json', 'original_json'):
        try:
            payload = json.loads(row.get(key) or '')
            if isinstance(payload, dict):
                return payload
        except (TypeError, ValueError):
            pass
    return {}
