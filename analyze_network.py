from scapy.all import PcapReader, IP, ARP
from mac_vendor_lookup import MacLookup


class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        self.pcap_path = pcap_path
        self.a_reader = PcapReader(self.pcap_path)
        self.info = []
        self.lookup = MacLookup()
        self.UNKNOWN = "unknown"
        self.scan_pcap()

    def scan_pcap(self):
        reader = PcapReader(self.pcap_path)
        for packet in reader:
            if ARP in packet:
                psrc = packet[ARP].psrc
                pdst = packet[ARP].pdst
                hwsrc = packet[ARP].hwsrc
                hwdst = packet[ARP].hwdst
                dsrc = {}
                dsrc["MAC"] = hwsrc
                dsrc["IP"] = psrc
                dsrc["VENDOR"] = self.lookup.lookup(hwsrc)
                self._add_info_to_list(dsrc)
                ddst = {}
                ddst["MAC"] = hwdst if hwdst != "ff:ff:ff:ff:ff:ff" else self.UNKNOWN
                ddst["IP"] = pdst if pdst != "255.255.255.255" else self.UNKNOWN
                ddst["VENDOR"] = (
                    self.lookup.lookup(ddst["MAC"])
                    if ddst["MAC"] != self.UNKNOWN
                    else self.UNKNOWN
                )

    def _add_info_to_list(self, new_packet):
        for packet in self.info:
            if packet["IP"] == new_packet["IP"] or packet["MAC"] == new_packet["MAC"]:
                # they are representing the same device
                packet["IP"] = (
                    new_packet["IP"]
                    if new_packet["IP"] != self.UNKNOWN
                    else packet["IP"]
                )
                packet["MAC"] = (
                    new_packet["MAC"]
                    if new_packet["MAC"] != self.UNKNOWN
                    else packet["MAC"]
                )
                packet["VENDOR"] = (
                    new_packet["VENDOR"]
                    if new_packet["VENDOR"] != self.UNKNOWN
                    else packet["VENDOR"]
                )
                return
        self.info.append(new_packet)

    def get_ips(self):
        """returns a list of ip addresses (strings) that appear in
        the pcap"""
        return [info_packet["IP"] for info_packet in self.info]

    def get_macs(self):
        """returns a list of MAC addresses (strings) that appear in
        the pcap"""
        return [info_packet["MAC"] for info_packet in self.info]

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

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "network analysis of a pcap file at path: " + self.pcap_path
