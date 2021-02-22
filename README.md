# rsyslog regex perfect file input plugin
Features:
* Extract data before first match within file stored as "(prematch@48577) firstMatch"
* Extract data from file with floating matchers, no limitation on just line matching when compiled with 'enableCase3 = 1;'

Work in progress features:
* Slice data between matches as "(oversized_message@48577) lastMatch"
