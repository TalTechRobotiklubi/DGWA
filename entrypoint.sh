#!/bin/sh

# Generate self-signed certificate using cert_gen.py
python cert_gen.py

# Start the server
python Discord_GWorkspace_Auth.py
