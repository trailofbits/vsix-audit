#!/bin/bash

# Run stage1.py to generate the extension using yo code
python3 stage1.py

# Run stage2.py to customize the extension with values from config.json
python3 stage2.py
