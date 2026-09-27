"""NetScan: a Qt front end for nmap and an all-round network toolkit.

Run it with ../netscan.py. Modules, roughly from the bottom up:
  system, scanning, names       platform helpers, nmap data and parsing, name lookups
  discovery, router, devices    background discovery, router SSH names, the device list
  internet, tools, report, cli  internet/speed tests, the Tools tab's engines, HTML report, command line
  theme, columns, widgets       look and feel, table layouts, custom widgets and workers
  window + *_tab, uptime, watch, export   the main window, assembled from one mixin per tab/feature
  app                           entry point
"""
