#!/bin/sh

# Generate self-signed certificate using cert_gen.py
python3 cert_gen.py

# Start the server
python3 Discord_GWorkspace_Auth.py
