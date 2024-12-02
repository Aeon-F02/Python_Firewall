import argparse
from src.cli.add_rule import add_rule_to_file
from src.cli.remove_rule import remove_rule_from_file
from src.cli.list_rules import list_all_rules

RULES_FILE = "default_rules.json"

def main():
    parser = argparse.ArgumentParser(description="Manage the Firewall.")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Add rule
    parser_add = subparsers.add_parser("add", help="Add a new rule")
    parser_add.add_argument("--src", required=True, help="Source IP address")
    parser_add.add_argument("--action", choices=["ALLOW", "BLOCK"], required=True, help="Action for the rule")

    # Remove rule
    parser_remove = subparsers.add_parser("remove", help="Remove an existing rule")
    parser_remove.add_argument("--src", required=True, help="Source IP address to remove the rule")

    # List rules
    parser_list = subparsers.add_parser("list", help="List all rules")

    args = parser.parse_args()

    if args.command == "add":
        add_rule_to_file(RULES_FILE, {"src": args.src, "action": args.action})
    elif args.command == "remove":
        remove_rule_from_file(RULES_FILE, args.src)
    elif args.command == "list":
        list_all_rules(RULES_FILE)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
