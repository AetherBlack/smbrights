
from impacket.smbconnection import SMBConnection
from impacket.examples.utils import parse_credentials, parse_target
# Types
from impacket.dcerpc.v5.srvs import SHARE_INFO_1
from impacket.smb import SharedFile
# Structs
from impacket.smb3structs import FILE_READ_DATA, FILE_WRITE_DATA
# Exceptions
from impacket import smbconnection

from typing import List, Dict
from colorama import Fore, Style

import argparse
import ntpath
import sys

parser = argparse.ArgumentParser(add_help = True, description = "SMB rights enumeration.")

parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

group = parser.add_argument_group('authentication')

group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                    '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                    'cannot be found, it will use the ones specified in the command '
                                                    'line')
group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                        '(128 or 256 bits)')

group = parser.add_argument_group('connection')

group.add_argument('-dc-ip', action='store', metavar="ip address",
                    help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                        'the target parameter')
group.add_argument('-target-ip', action='store', metavar="ip address",
                    help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                        'This is useful when target is the NetBIOS name and you cannot resolve it')
group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                    help='Destination port to connect to SMB Server')

group = parser.add_argument_group("rights")

group.add_argument("-share", action="store", help="Name of the share to inspect rights. If omitted list shares.")
group.add_argument("-recurse", action="store_true", help="Check files recursively.")
group.add_argument("-right", choices=["read", "write"], action="store", help="Right to check.")

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

options = parser.parse_args()

domain, username, password, address = parse_target(options.target)

if not len(domain):
    domain, username, password = parse_credentials(options.target)
    address = domain

if options.target_ip is None:
    options.target_ip = address

if domain is None:
    domain = ''

if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
    from getpass import getpass
    password = getpass("Password:")

if options.aesKey is not None:
    options.k = True

if options.hashes is not None:
    lmhash, nthash = options.hashes.split(':')
else:
    lmhash = ''
    nthash = ''

DEBUG = options.debug
RIGHT = options.right

smbClient = SMBConnection(address, options.target_ip, sess_port=int(options.port))
if options.k is True:
    smbClient.kerberosLogin(username, password, domain, lmhash, nthash, options.aesKey, options.dc_ip)
else:
    smbClient.login(username, password, domain, lmhash, nthash)

shares: Dict[str, SHARE_INFO_1] = dict()

sharesList: List[SHARE_INFO_1] = smbClient.listShares()

for share in sharesList:
    shares[share["shi1_netname"][:-1]] = share

if options.share is None:
    print("[*] Listing shares")

    for share in shares.keys():
        print(share)
    
    sys.exit(0)

if options.share not in shares.keys():
    print(f"[!] Share '{options.share}' not found!")
    sys.exit(1)

treeId = smbClient.connectTree(options.share)

def checkFilesRights(smbClient: SMBConnection, share: str, pwd: str, recurse: bool):

    path = ntpath.join(pwd, "*")

    try:
        pathFiles = smbClient.listPath(share, path)
    except smbconnection.SessionError:
        return

    for file in pathFiles:
        file: SharedFile
        # Skip this kind of files
        if file.get_shortname() in [".", ".."]: continue

        fullPath = ntpath.join(pwd, file.get_longname())

        if DEBUG:
            print(f"[DEBUG] File long name {fullPath}")

        if file.is_directory() and recurse:
            checkFilesRights(smbClient, share, fullPath, recurse)

        try:
            fileId = smbClient.openFile(treeId, fullPath, desiredAccess=FILE_READ_DATA)
            smbClient.closeFile(treeId, fileId)
            if RIGHT is None or RIGHT == "read":
                print(f"[*] File {Fore.BLUE}{fullPath}{Style.RESET_ALL} can be {Fore.GREEN}READ{Style.RESET_ALL}")
        except smbconnection.SessionError:
            pass

        try:
            fileId = smbClient.openFile(treeId, fullPath, desiredAccess=FILE_WRITE_DATA)
            smbClient.closeFile(treeId, fileId)
            if RIGHT is None or RIGHT == "write":
                print(f"[*] File {Fore.BLUE}{fullPath}{Style.RESET_ALL} can be {Fore.GREEN}WRITE{Style.RESET_ALL}")
        except smbconnection.SessionError:
            pass

checkFilesRights(smbClient, options.share, "\\", options.recurse)
