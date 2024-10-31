# iot_authentication
An authentication server made for drawnapart fingerprints. Devices access the authentication servers drawnapart fingerprint creator,
which then checks the fingerprint against three models:
1. Classification model checks if the drawnapart label matches the label the devices calls itself.
2. Anomaly model checks the invidiual traces on the fingerprint, attempts to detect fingerprint spoofing.
3. Authentication model takes 8 fingerprints, and decides if the device is good or bad.

# Installation
1. Make sure uv is installed: https://docs.astral.sh/uv/getting-started/installation/
2. `uv run sanic --dev app`

# Usage
Navigate a device to: `http://localhost:8000/static/onscreen.html?device_id=odroid1&malicious=true`. device_id can be any value, for malicious pass either true or false