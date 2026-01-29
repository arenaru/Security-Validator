import importlib, sys, os

# Ensure repo root is on sys.path so local packages (components/, utils/) can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

mods = [
 'components.ui_sslv3',
 'components.ui_tlsv10',
 'components.ui_tlsv11',
 'components.sidebar',
 'utils.scanner_engine',
 'utils.db_loader',
 'utils.pdf_gen'
]
ok = True
for m in mods:
    try:
        importlib.import_module(m)
        print(m, 'OK')
    except Exception as e:
        ok = False
        print(m, 'ERROR:', e)
if not ok:
    sys.exit(1)
print('SMOKE TESTS PASSED')
