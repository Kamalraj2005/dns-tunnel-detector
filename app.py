"""
Root Entry Point for Streamlit Community Cloud and Containerized Deployments.
Redirects execution seamlessly to dashboard/app.py.
"""
import os
import sys
import runpy

# Ensure project root is at the head of sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

dashboard_script = os.path.join(BASE_DIR, "dashboard", "app.py")
runpy.run_path(dashboard_script, run_name="__main__")
