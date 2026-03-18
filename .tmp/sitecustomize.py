import sys
for p in ('/app/backend','/app'):
    if p not in sys.path:
        sys.path.insert(0, p)
