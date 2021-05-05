
# check black list to black - 403 forbident
def check_blocked(blocked, details):
    if not (details["server_url"] + ":" + str(details["server_port"])) in blocked:
        return False
    return True

