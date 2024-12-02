class PacketFilter:
    def __init__(self, rule_engine):
        self.rule_engine = rule_engine  # Accept the RuleEngine instance directly

    def filter_packet(self, packet):
        action = self.rule_engine.check_packet(packet)
        if action == "BLOCK":
            print(f"Packet blocked: {packet.summary()}")
            return False
        elif action == "ALLOW":
            print(f"Packet allowed: {packet.summary()}")
            return True
        return False
