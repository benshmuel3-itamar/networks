from mac_vendor_lookup import InvalidMacError, MacLookup, VendorNotFoundError
from scapy.all import ARP, ICMP, IP, Ether, PcapReader


class AnalyzeNetwork:
    LINUX = "linux or linux based system (android and such)"
    WINDOWS = "windows"
    UNKNOWN = "unknown"
    needed_keys = ("OS", "MAC", "VENDOR", "IP")
    LINUX_PING = bytes(range(16, 56))
    WINDOWS_PING = b"abcdefghijklmnopqrstuvwabcdefghi"
    PINGS = {LINUX_PING: LINUX, WINDOWS_PING: WINDOWS}

    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        self.pcap_path = pcap_path
        self.info = []
        self.lookup = MacLookup()
        self._scan_pcap()

    def _scan_pcap(self):
        """
        reads through the pcap file and orginizes all the info into a list.
        """
        reader = PcapReader(self.pcap_path)
        for packet in reader:
            if ARP in packet:
                self._process_arp(packet)
            if ICMP in packet:
                self._process_icmp(packet)
        reader.close()

    def _process_icmp(self, packet):
        # we can not know the MAC addr of either device (because they change on the way)
        dsrc_phys = {}
        dsrc_phys["MAC"] = packet[Ether].src
        dsrc_phys["VENDOR"] = self._get_vendor(dsrc_phys["MAC"])
        ddst_phys = {}
        ddst_phys["MAC"] = packet[Ether].dst
        ddst_phys["VENDOR"] = self._get_vendor(ddst_phys["MAC"])
        dsrc_ip = {}
        dsrc_ip["IP"] = packet[IP].src
        if 108 <= packet[IP].ttl <= 128:
            dsrc_ip["OS"] = AnalyzeNetwork.WINDOWS
        elif 44 <= packet[IP].ttl <= 64:
            dsrc_ip["OS"] = AnalyzeNetwork.LINUX
        ddst_ip = {}
        ddst_ip["IP"] = packet[IP].dst
        if packet[ICMP].load[16:] in AnalyzeNetwork.PINGS:
            if packet[ICMP].type == 8:
                dsrc_ip["OS"] = AnalyzeNetwork.PINGS[packet[ICMP].load[16:]]
            if packet[ICMP].type == 0:
                ddst_ip["OS"] = AnalyzeNetwork.PINGS[packet[ICMP].load[16:]]
        if packet[IP].ttl in {64, 128}:
            self._add_multiple_infos(dsrc_phys | dsrc_ip, ddst_phys | ddst_ip)
        else:
            self._add_multiple_infos(dsrc_phys, dsrc_ip, ddst_ip, ddst_phys)

    def _add_multiple_infos(self, *args):
        for packet in args:
            self._add_info_to_list(packet)

    def _process_arp(self, packet):
        """
        gets the data from an ARP packet
        """
        psrc = packet[ARP].psrc
        pdst = packet[ARP].pdst
        hwsrc = packet[ARP].hwsrc
        hwdst = packet[ARP].hwdst
        dsrc = {}
        dsrc["MAC"] = hwsrc
        dsrc["IP"] = psrc
        dsrc["VENDOR"] = self._get_vendor(hwsrc)
        self._add_info_to_list(dsrc)
        ddst = {}
        ddst["MAC"] = hwdst if hwdst != "ff:ff:ff:ff:ff:ff" else AnalyzeNetwork.UNKNOWN
        ddst["IP"] = pdst if pdst != "255.255.255.255" else AnalyzeNetwork.UNKNOWN
        ddst["VENDOR"] = self._get_vendor(ddst["MAC"])
        self._add_info_to_list(ddst)

    def _get_vendor(self, macaddr):
        """
        uses a library to get the vendor from the mac address
        """
        try:
            vendor = self.lookup.lookup(macaddr)
            return vendor
        except VendorNotFoundError, InvalidMacError:
            return AnalyzeNetwork.UNKNOWN

    def _null_fill_packet(self, packet):
        """
        feels in unknown for all the missing keys in the info packet
        """
        for key in AnalyzeNetwork.needed_keys:
            if key not in packet:
                packet[key] = AnalyzeNetwork.UNKNOWN
        return packet

    def _add_info_to_list(self, new_packet):
        """
        adds an to the infolist, making sure not to have two items that represent the same computer.
        """
        new_packet = self._null_fill_packet(new_packet)
        for packet in self.info:
            if (
                packet["IP"] == new_packet["IP"] != AnalyzeNetwork.UNKNOWN
                or packet["MAC"] == new_packet["MAC"] != AnalyzeNetwork.UNKNOWN
            ):
                # they are representing the same device
                for key in packet:
                    packet[key] = (
                        new_packet[key]
                        if new_packet[key] != AnalyzeNetwork.UNKNOWN
                        else packet[key]
                    )
                return
        self.info.append(new_packet)

    def get_ips(self):
        """returns a list of ip addresses (strings) that appear in
        the pcap"""
        return [
            info_packet["IP"]
            for info_packet in self.info
            if info_packet["IP"] != AnalyzeNetwork.UNKNOWN
        ]

    def get_macs(self):
        """returns a list of MAC addresses (strings) that appear in
        the pcap"""
        return [
            info_packet["MAC"]
            for info_packet in self.info
            if info_packet["MAC"] != AnalyzeNetwork.UNKNOWN
        ]

    def get_info_by_mac(self, mac):
        """returns a dict with all information about the device with
        given MAC address"""
        for info_pack in self.info:
            if info_pack["MAC"] == mac:
                return info_pack

    def get_info_by_ip(self, ip):
        """returns a dict with all information about the device with
        given IP address"""
        for info_pack in self.info:
            if info_pack["IP"] == ip:
                return info_pack

    def get_info(self):
        """returns a list of dicts with information about every
        device in the pcap"""
        return self.info

    def guess_os(self, device_info):
        return device_info["OS"]

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "network analysis of a pcap file at path: " + self.pcap_path
