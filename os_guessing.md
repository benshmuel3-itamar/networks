# heuristics for guessing OS:

* ICMP: different OSs use different TTL (time to live) for ping packets.
* windows: 128. linux: 64. so we can guess based on that.
* additionally, by default windows sends 32 bytes, while linux sends 40. however, this is more reasonable to change so the implementation relies on the TTL.
