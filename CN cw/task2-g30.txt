import ipaddress

class Firewall:
    def __init__(self):
        self.firewall_rules = [] # List to store the firewall rules within the program

    def add_rule_command(self, rule_number=None, direction=None, address=None):
        if not self.validate_address(address): # Check if IP adress is valid
            print(f"Invalid Address '{address}'") # If not print out error message
            return

        if rule_number is None: # If rule number is not provided then
            rule_number = 1 # Set firewall rule priority to 1 by default
        else:
            int(rule_number) # Else set firewall rule with the given rule number

        if rule_number <= 0: # Firewall rule cannot be less than 1. If it is
            print("Please input rule number more than or equal to 1") # Error message is printed out to tell user
            return

        new_rule = { # Format of how the adding of rules should be
            "rule_number": rule_number,  # Start with rule number
            "direction": direction if direction in ["-in", "-out"] else "-in and -out", # Then direction allowed which in, out or both
            "address": address # Then IP address either single or a range
        }

        for rule in self.firewall_rules: # For loop to adjust rule adding based on rule number
            if rule['rule_number'] >= rule_number: # If the rule number is more than or equal to the rule numbers in the list then
                rule['rule_number'] += 1 # increment by 1 to adjust the list according to the new rule added

        self.firewall_rules.append(new_rule) # Add the new rules to the list of rules
        self.firewall_rules.sort(key=lambda x: x['rule_number']) # Sort the rule based on rule numbers to make sure the top priority is the first (rule number 1)

        print(f"Rule added: {new_rule}") # Once the rule is added send the user a confirmation that the rule has been added

    
    def remove_rule_command(self, rule_number, direction=None):
        updated_rules = [] # List to store updated rules (This will later be updated into the main firewall rule list)
        rule_found = False # Flag to indicate if the rule is found or not

        for rule in self.firewall_rules: # Iterate through the firewall list with all the rules added from before
            if rule['rule_number'] == rule_number: # If the rule number is found within the firewall list then
                rule_found = True # Set the flag to true to indicate the rule is found
                if direction is None:  # If the rule was mentioned without a direction then the full rule is removed
                    print(f"Rule removed: {rule}") # Tells the user the rule is removed for confirmation
                    continue # Since the rule is removed there is no need to update and it can skip this

                if rule['direction'] == "-in and -out": # If the direction is both -in and -out for a rule then (If you would like to remove one or the other)
                    if direction == "-in": # If the direction mentioned to remove was -in then
                        rule['direction'] = "-out" # Keep the -out direction
                    else:
                        rule['direction'] = "-in" # Else keep the direction as -in
                    print(f"Rule updated: {rule}") # Tells the user the rule was updated with a confrimation
                    updated_rules.append(rule) # Updates the updated_rule list with the new rule 

                elif rule['direction'] == direction: # If the rule number with a certain direction was provided than that rule can be removed (-in or -out)
                    print(f"Rule removed: {rule}") # Tells the user the rule has been removed for confirmation
                    continue # No need to update the updated rule list since it has been removed and it can skip this
                else:
                    print(f"Invalid direction at rule {rule_number}.") # If the rule number with the specified direction is not found it gives a error
                    updated_rules.append(rule) # Keeps the selected rule as it is no need to update it or remove
            else:
                updated_rules.append(rule) # Adds all the unedited rules to the updated list to make sure they are given back to the firewall list

        if not rule_found: #  If a rule was not found then
            print(f"Rule number: {rule_number} does not exist.") # Print a error message indicating to the user that the mentioned rule was not found
            return

        for i, rule in enumerate(updated_rules): # Once the rules have been removed and edited a for loop is created to make sure the priority of rules are set correctly
            rule['rule_number'] = i + 1 # Increment the rule numbers by 1

        self.firewall_rules = updated_rules # Update the all the edited and removed rules to the firewall list

    def list_rules_command(self, rule_number=None, direction=None, address=None):
        listed_rules = [] # List to store the rules that match the given direction, rule number, and address
        for rule in self.firewall_rules: # Iterate through all the rules within the firewall list
            if rule_number is not None and rule['rule_number'] != rule_number: # Filter through all the rule numbers that are not mentioned
                continue
            if direction is not None and rule['direction'] not in {direction, "-in and -out"}: # Filters through all the directions that are not metnioned
                continue
            if address is not None and not self.address_in_range(rule['address'], address): # Filters through all the IP addresses that are not mentioned
                continue
            listed_rules.append(rule) # Adds the rule specified into the list listed_rules

        if listed_rules: # If the rule specified was found then
            print("Firewall Rules:") # Print this statement before the rules to specify that whats below are the specified rules
            for rule in listed_rules: # For loop to iterate through all the rules added into the listed_rules list
                print(f"[Rule {rule['rule_number']}: {rule['direction']} {rule['address']}]") # Prints out the rules in this format to the user
        else: # If the rule(s) is not found then
            print("No firewall rules found.") # Prints this back to the user to tell them the firewall rules mentioned were not found    


    def address_in_range(self, rule_address, filter_address):
        filter_start, filter_end = ( # Converts the address specified into IPv4 address objects to seek in the list
            map(ipaddress.IPv4Address, filter_address.split("-")) # Converts the address to IPv4 address objects (Single address)
            if "-" in filter_address # If its a "-" then it splits it into a range
            else (ipaddress.IPv4Address(filter_address), ipaddress.IPv4Address(filter_address)) # Splits it into a range of start and end addresses
        )
        rule_start, rule_end = ( # Coverts the address mentioned into IPv4 address objects to add to the list
            map(ipaddress.IPv4Address, rule_address.split("-")) # Converts the address to IPv4 address objects (Single address)
            if "-" in rule_address # If its a "-" then it splits it into a range
            else (ipaddress.IPv4Address(rule_address), ipaddress.IPv4Address(rule_address)) # Splits it into a range of start and end addresses
        )
        return filter_start <= rule_start <= filter_end or filter_start <= rule_end <= filter_end # Returns true if start rule or end rule is within the mentioned filter start or end
    



    def validate_address(self, address):
        try: # A try and catch block to verify correct IP addresses given either single or a range
            if "-" in address: # If the address has a "-" then a range is being mentioned
                start, end = address.split("-") # Splits the range into start and end ranges
                ip_start = ipaddress.IPv4Address(start) # Start IP address conversion
                ip_end = ipaddress.IPv4Address(end) # End IP address conversion
                return ip_start <= ip_end  # Ensure the start range is smaller or equal to the end IP range
            else: # Else its probably a single IP addres
                ipaddress.IPv4Address(address) # Convert the given address to a a valid IP address
                return True # Then return true if its correct else
        except ValueError: # Throw a value error and then
            return False # Return false because the address was invalid


def parse_input(input_str):
    parts = input_str.split() # Split input into parts (each space is one part)
    command = parts[0] # Command such as add, remove, etc are considered the 0 part (first part)
    rule_number = None # rule_number is set to none
    direction = None # direction is set to none
    address = None # address is set to none

    for part in parts[1:]: # For loop to iterate through the full command to see which part belongs to which
        if part.isdigit(): # The part with a digit or a int is the rule number
            rule_number = int(part) # rule_number is equal to the int part
        elif part in ["-in", "-out"]: # the -in or -out is the direction part
            direction = part # direction is equal to the direction part
        elif "." in part: # The "." means an address is being typed and hence a IP address
            address = part # address is equal to the address part

    return { # This then all combines and is returned as a dictionary value with a key value pair
        "command": command,
        "rule_number": rule_number,
        "direction": direction,
        "address": address
    }


if __name__ == "__main__":
    firewall = Firewall()
    print("---------------------------------------------------------------------------")
    print("Welcome to F20CN Firewall Task!!")
    print("--------------------------------------------------------------------------")
    print("\n---------------------------------------------------------------------------")
    print("To add: add [rule number] [-in|-out] [address]")
    print("To remove: remove [rule number] [-in|-out] | remove [rule number]")
    print("To list: list [rule number] [-in|-out] [address] | list")
    print("---------------------------------------------------------------------------")
    print("\n---------------------------------------------------------------------------")

    while True:
        # Get user input
        user_input = input("\nPlease Enter command (add/remove/list/syntax/exit): ").strip()
        if user_input.lower() == "exit":
            print("\nExiting firewall management, Goodbye......")
            break

        # Parse and handle commands
        parsed = parse_input(user_input)
        if parsed["command"] == "add":
            if not parsed["address"]:
                print("Error: Address is required for the 'add' command.")
                continue
            print("\n---------------------------------ADD------------------------------------------")
            firewall.add_rule_command(
                rule_number=parsed["rule_number"],
                direction=parsed["direction"],
                address=parsed["address"]
            )
            print("\n----------------------------------------------------------------------------")

        elif parsed["command"] == "remove":
            if not parsed["rule_number"]:
                print("Error: Rule number is required for the 'remove' command.")
                continue
            print("---------------------------------REMOVE------------------------------------------")
            firewall.remove_rule_command(
                rule_number=parsed["rule_number"],
                direction=parsed["direction"]
            )
            print("----------------------------------------------------------------------------")

        elif parsed["command"] == "list":
            print("---------------------------------RULES------------------------------------------")
            firewall.list_rules_command(
                rule_number=parsed["rule_number"],
                direction=parsed["direction"],
                address=parsed["address"]
            )
            print("----------------------------------------------------------------------------")

        elif parsed["command"] == "syntax":
            print("---------------------------------SYNTAX------------------------------------------")
            print("----------------------------------------------------------------------------")
            print("To add: add [rule number] [-in|-out] [address]")
            print("To remove: remove [rule number] [-in|-out]")
            print("To list: list [rule number] [-in|-out] [address]")
            print("----------------------------------------------------------------------------")
            print("----------------------------------------------------------------------------")

        else:
            print("Please use one of these commands listed: (add/remove/list/syntax/exit)")
