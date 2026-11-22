"""Construction stages shared by inventory and monthly-book APIs."""
STAGES = ('Demolished', 'Basement Digging', 'Basement Slab Completed', 'FF Slab Completed', 'SF Slab Completed', 'TF Slab Completed', 'Structure Ready', 'Interior Work Going On', 'Final Stage')

def validate_stage(value):
    if not isinstance(value, str) or (value != '' and value not in STAGES):
        raise ValueError('Select a valid construction stage.')
    return value
