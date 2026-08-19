"""
Main Entry Point - Phase 4 System Integration
Enhanced Facial Authentication System with Hybrid IDS
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from GUI.main_gui import run

if __name__ == "__main__":
    print("=" * 70)
    print("ENHANCED FACIAL AUTHENTICATION SYSTEM v1.0")
    print("Phase 4: System Integration & GUI Development")
    print("Student: Omu John Efu (CYB/23U/3983)")
    print("=" * 70)
    print()
    
    try:
        run()
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
