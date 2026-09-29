#!/usr/bin/env python
"""Simple script to run the uvicorn server"""
import sys
import os

# Ensure we can import app
sys.path.insert(0, os.path.dirname(__file__))

try:
    from app.main import app
    print("✓ App imported successfully")

    import uvicorn
    print("✓ Uvicorn imported successfully")

    print("\nStarting server on http://0.0.0.0:8000")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )

except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
