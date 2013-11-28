MKBRUTUS
========

# MKBRUTUS.py v1.0.0 - Password bruteforcer for MikroTik devices or boxes running RouterOS
#
# AUTHORS:
# Ramiro Caire   - email: ramiro.caire@gmail.com  / Twitter: @rcaire
# Federico Massa - email: fgmassa@vanguardsec.com / Twitter: @fgmassa
# https://github.com/mkbrutusproject/mkbrutus
#
# SUMMARY:
# Some boxes running Mikrotik RouterOS (3.x or newer) have the API port enabled (by default, in the port 8728/TCP)
# for administrative purposes instead SSH, Winbox or HTTPS (or have all of them). This is (another) attack vector as it
# might be possible to perform a bruteforce to obtain valid credentials if no protection is available on that port.
# As the API uses a specific privative protocol, some code published by the vendor was included.
# Python 3.x is required in order to run this tool.
#
# DISCLAIMER:
# This tool is intended only for testing Mikrotik devices security in ethical pentest or audits process.
# The authors are not responsible for any damages you use this tool.

