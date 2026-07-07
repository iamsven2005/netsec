#!/usr/bin/env python3
"""
Wrapper for standalone executable.
Imports and runs main.py from the packaged toolkit.
"""

import sys
import os

# Add current directory to path so imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run main
try:
    import main
    main.main()
except KeyboardInterrupt:
    print("\n[*] Interrupted by user")
    sys.exit(0)
except Exception as e:
    print(f"[!] Fatal error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
