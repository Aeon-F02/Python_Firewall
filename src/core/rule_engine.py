import json

class RuleEngine:
    def __init__(self, rules_file="default_rules.json"):
        self.rules = []
        self.load_rules(rules_file)

    def load_rules(self, rules_file):
        try:
            with open(rules_file, "r") as file:
                self.rules = json.load(file)
                print("Rules loaded successfully.")
        except FileNotFoundError:
            print("Rules file not found. Starting with no rules.")
    
    def add_rule(self, rule):
        self.rules.append(rule)
        print(f"Added rule: {rule}")

    def remove_rule(self, rule):
        if rule in self.rules:
            self.rules.remove(rule)
            print(f"Removed rule: {rule}")
        else:
            print("Rule not found.")
    
    def check_packet(self, packet):
        # Example: Simple rule match for IP source/destination
        for rule in self.rules:
            if "ip" in packet and packet["ip"].src == rule.get("src"):
                return rule.get("action", "ALLOW")
        return "ALLOW"
