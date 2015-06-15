wifi_dump-tmpfs
===============
The tool collects wireless traces from home networks. It collects Physical layer and MAC layer information per frame.
It collects physical layer information as queuing delays, errors counters, signal strength in the device driver. 
At the mac layer, it collects the mac-layer headers.
We collect anonymized mac address of the device as a unique id. We do not collect any sensitive information 
regarding users like the IP address of the websites visited, or any other information at the IP layer.

You should the kernel patch in mac80211-quirm directory to make use of this userland binary.
It runs with specific compat-wireless code (driver and mac80211 networking kernel stack.


Details: 
TRANSPORT_LAYER_CAPTURE flag allows one to capture TCP/UDP headers also.
DEBUG flags allows you to compile the parts of the code which were used only while testing phase
