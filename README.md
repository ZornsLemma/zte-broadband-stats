# ZTE MC888 5G router statistics logger

## Overview

This repository contains some simple Python code which can be used to periodically log broadband statistics (data use, SINR, etc) from a ZTE MC888 5G router to a CSV file. It's possible it will work for some other ZTE routers, but I haven't been able to test this.

Even if this isn't of any use to you you might still be interested in the start_session() and get_raw_router_values() functions, which show how to log in to the router's web GUI and extract information programmatically.

## Basic instructions

You need to create a configuration file somewhere and then run this code using something like:

```
python3 bbs.py --config my-config-file --verbose
```

There is an [example configuration file](bbsrc.example) which also contains some comments describing the available options. To get started you should just be able to copy that and edit the three values underneath "[router]" at the top to tell the script how to log in to your router.

If you want the code to perform a test download to check your connection speed, add "--download". If you want the code to decide at random whether to perform a test download, add "--download-probability p" where p is a probability in the range 0-100. (p can optionally be followed by a "%" symbol, but it is always interpreted as a percentage probability whether the "%" symbol is present or not.)

I have this set up to run from a cron job every 15 minutes using "--download-probability 1 --polite". This gives me roughly one download test a day so I have some historical data to look back on if my connection seems to be developing problems, without using up too much of my own or the test sites' bandwidth. --polite tries to avoid kicking me out of the router's web GUI if I am using it myself in a browser.

## Possible problems

I have data use tracking enabled in the router's web GUI. If you don't have this turned on, things will probably work but it's possible attempting to retrieve these statistics will fail noisily. Including "monthly_tx_bytes,monthly_rx_bytes" in the suppress_columns entry in the config file will probably work around this.

## Adding more statistics

You can use the developer tools in a web browser to watch the network requests and responses made while you're logged in to the router's web GUI. Looking at the JSON responses should allow you to identify the internal name for the statistic you're interested in, and you can then add a corresponding entry in the statistics_list in the code.
