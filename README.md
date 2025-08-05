# SourceCoin
## Overview

A simplified blockchain where a server runs a hidden countdown timer and rewards all active miners with 50 coins when it ends.

## How It Works
The server runs on [my website](sourceguy.pythonanywhere.com) and manages the countdown timer (random between 200–600 seconds).

Miners connect to the server and continuously participate by running the miner software.

When the countdown reaches zero, the server automatically rewards all currently active miners with 50 coins each.

The countdown timer is hidden from miners to prevent abuse.

# Getting Started
## Prerequisites
Python.

Download the miner from the source code.

## Running the Miner
Download the .py file

Then install requirements.txt:

`pip install -r requirements.txt`

Finally take the .py and run it in python.

# Security and Fairness
The server handles all timing and reward logic to prevent cheating.

The server code is open-source for transparency.

# API

### See balance
`GET https://sourceguy.pythonanywhere.com/balance/{User's Address}`

### There are other API endpoints that i'm working on making public.


# Contribution
Please make sure to include comments where nessesary.

# Disclaimer
this project isnt a real currency, its for educational purposes only!
