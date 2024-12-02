from scapy.all import sniff

class PacketSniffer:
    def __init__(self, interface, packet_filter, logger):
        self.interface = interface
        self.packet_filter = packet_filter
        self.logger = logger

    def packet_handler(self, packet):
        """
        Handle incoming packets: print summaries and pass to filter or rule engine.
        """
        print(f"Captured packet: {packet.summary()}")
        # Here you could apply filtering or pass to rule engine
        # For now, we'll just pass the packet to the filter
        self.packet_filter.filter_packet(packet)

    def start(self):
        """
        Start sniffing on the specified network interface.
        """
        print(f"Starting packet sniffer on {self.interface}...")
        sniff(iface=self.interface, prn=self.packet_handler, store=False)
