import ipaddress
import sys
from enum import Enum
import re

from python_hosts import Hosts, HostsEntry

class About():
    def __init__(self):
        self.__prog_name = 'UniImage Kit',
        self.__version = '0.0.3'
        self.__description = 'Manage 200ms/alpinenet_dev2 settings'
        self.__author = "Mateusz Piwek"

    def print_help(self):
        print(f" [add|del] <ip addres> (host name, ....)")

    def print_version(self):
        print(f"Version: {self.__version}, by {self.__author}")


class Arguments:
    class parse_states(Enum):
        ERROR = 3
        PASSED = 1
        TRY_NEXT = 2

    def __init__(self):
        self.__hosts = Hosts()
        # default operation
        self._op = self.__hosts.add
        self._addr = None
        self.__hosts = []

    def exec(self):
        if isinstance(self._addr, ipaddress.IPv4Address):
            ip_family = 'ipv4'
        else:
            ip_family = 'ipv6'

        entry = HostsEntry(entry_type=ip_family, address=str(self._addr), names=self.__hosts)

    @staticmethod
    def just_info(arg: str):
        match arg:
            case '-h' | '--help':
                About().print_help()
                return True
            case '-v' | '--version':
                About().print_version()
                return True

        return False

    def parse_operation(self, arg: str):
        match arg:
            case 'add':
                self._op = self.__hosts.add
            case 'del':
                self._op = self.__hosts.remove_all_matching
            case _:
                return Arguments.parse_states.TRY_NEXT

        return Arguments.parse_states.PASSED

    def parse_addr(self, arg: str):
        try:
            ipaddress.ip_address(arg)
        except ValueError:
            return Arguments.parse_states.ERROR

        return Arguments.parse_states.PASSED

    def parse_name(self, arg: str):
        name = arg.strip()
        # based on: https://stackoverflow.com/questions/2532053/validate-a-hostname-string

        if len(name) > 255:
            return Arguments.parse_states.ERROR

        labels = name.split(".")

        if len(labels[:-1]):
            # if domain name ends with dot, then last label is empty
            # don't ended domain names are valid, but to don't
            # have validation faile later on rm last empty string
            del labels[-1]

        # the TLD must be not all-numeric
        if re.match(r"[0-9]+$", labels[-1]):
            return Arguments.parse_states.ERROR

        allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)

        res = all(allowed.match(label) for label in labels)

        if res == False:
            return Arguments.parse_states.ERROR

        self.__hosts.append(name)
        return Arguments.parse_states.PASSED

def parse_args(argv: [], continue_check_on_error = True):
    iterations = 0
    idx = 1
    level = 0
    last_level = False
    errors = []
    arguments = Arguments()

    parse_chain = [arguments.parse_operation, arguments.parse_addr, arguments.parse_name]

    if len(argv) == 1:
        arg = ''
    else:
        arg = argv[1]

    parse = parse_chain[0]

    while not last_level or arg != '':
        if Arguments.just_info(arg):
            break

        res = parse(arg)
        if res == Arguments.parse_states.ERROR:
            errors.append(f"Error while parsing argument {arg}, position: {idx}")
            if not continue_check_on_error:
                break

        if arg != '' and res == Arguments.parse_states.PASSED:
            idx += 1
            if len(argv) == idx:
                arg = ''
            else:
                arg = argv[idx]

        if not last_level:
            level += 1
            if len(parse_chain) == level:
                last_level = True
            else:
                parse = parse_chain[level]

        iterations += 1
        if iterations > 300:
            raise Exception("Infinite loop ..., something wrong in code, other errors: \n" + '\n'.join(errors))

    if errors:
        raise Exception('\n'.join(errors))

    return arguments

def main(argv: []):
    pass

if __name__ == "__main__":
    progr = parse_args(sys.argv)
    progr.exec()




