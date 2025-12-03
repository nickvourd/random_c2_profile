import datetime
import random
import string
from core.html_content import *
from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem, HardwareType, SoftwareType, Popularity

###################
# Helper Functions and Variables

# Create list from object-wordlist
objects = []
with open("core/object-wordlist.txt", "r") as f:
    objects = f.read().split()

# Create list from object-wordlist
actions = []
with open("core/action-wordlist.txt", "r") as f:
    actions = f.read().split()

def get_date():
    """ Formatted Date/Time String """

    date = datetime.datetime.now()	
    dateStr = date.strftime("%Y%m%d_%H%M")
    return dateStr

def get_random_string(length):
    # Return random string of uppercase characters of provided length
    # choose from all uppercase letter
    letters = string.ascii_uppercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def get_random_alphanum(length):
    # Return random string of uppercase/digits characters of provided length
    alphanum = string.ascii_uppercase + string.digits
    result_str = ''.join(random.choice(alphanum) for i in range(length))
    return str(result_str)

def get_random_object():
    # Return random object from list
    return random.choice(objects)

def get_random_action():
    # Return random action from list
    return random.choice(actions)

def get_random_uri():
    # Return random URI as /<random action>/<random object>?<random 2 char>=<random alphanum>
    result = "/" + get_random_action() + "/" + get_random_object() + "/" + get_random_alphanum(random.randint(8,12))
    return result

def get_random_bytearry(length):
    # Return random bytearray as \x formatted strng
    # example: \x74\x90\xc9\xf2
    # hex value range
    low = 80
    high = 255
    result = ""
    for i in range(length):
        h = random.randint(low,high)
        hh = bytearray([h]).hex()
        result += '\\x' + hh
    return str(result)

def get_http_client_accept():
    # Return Random HTTP Header Accept from list
    accepts = ['text/html', 'application/xhtml+xml', 'application/xml', 'image/*', 'application/json']
    picks = random.sample(accepts,3)
    accept = '"Accept" "' + picks[0] + ", " + picks[1] + ", " + picks[2] + '"'
    return accept

def get_http_client_accept_language():
    # Return Random HTTP Header Accept-Language from list
    languages = ["af", "sq", "ar-dz", "ar-bh", "ar-eg", "ar-iq", "ar-jo", "ar-kw", "ar-lb", "ar-ly", "ar-ma", "ar-om", "ar-qa", "ar-sa", "ar-sy", "ar-tn", "ar-ae", "ar-ye", "eu", "be", "bg", "ca", "zh-hk", "zh-cn", "zh-sg", "zh-tw", "hr", "cs", "da", "nl-be", "nl", "en", "en-au", "en-bz", "en-ca", "en-ie", "en-jm", "en-nz", "en-za", "en-tt", "en-gb", "en-us", "et", "fo", "fa", "fi", "fr-be", "fr-ca", "fr-lu", "fr", "fr-ch", "gd", "de-at", "de-li", "de-lu", "de", "de-ch", "el", "he", "hi", "hu", "is", "id", "ga", "it", "it-ch", "ja", "ko", "ko", "ku", "lv", "lt", "mk", "ml", "ms", "mt", "no", "nb", "nn", "pl", "pt-br", "pt", "pa", "rm", "ro", "ro-md", "ru", "ru-md", "sr", "sk", "sl", "sb", "es-ar", "es-bo", "es-cl", "es-co", "es-cr", "es-do", "es-ec", "es-sv", "es-gt", "es-hn", "es-mx", "es-ni", "es-pa", "es-py", "es-pe", "es-pr", "es", "es-uy", "es-ve", "sv", "sv-fi", "th", "ts", "tn", "tr", "uk", "ur", "ve", "vi", "cy", "xh", "ji", "zu"]
    language = '"Accept-Language" "' + random.choice(languages) + '"'
    return language

def get_http_client_accept_encoding():
    # Return Random HTTP Header Accept-Encoding from list
    accept_encodings = ['gzip', 'br', 'identity', '*','compress']
    picks = random.sample(accept_encodings, 2)
    accept_encoding = '"Accept-Encoding" "' + picks[0] + ", " + picks[1] + '"'
    return accept_encoding   

def get_http_metadata_transform():
    # Return random Data Transform Language (https://www.cobaltstrike.com/help-malleable-c2)
    transformations = ['base64url','netbios','netbiosu']
    return random.choice(transformations)

def get_http_content():
    # Return random blob of HTTP response content
    # contents variable is stored in html_contents.py
    
    # Select items from random
    # Ensure " is escaped in a format usable by the profile
    escaped = random.choice(contents).replace("\\","\\\\").replace('"','\\"')
    content = ''.join(char for char in escaped if ord(char) < 128)
    return content

def get_nops():
    # Return random bytearry of NOP equvilants as \x formatted string
    # short list of nop equivalents

    # | LENGTH  |           ASSEMBLY                       |         BYTE SEQUENCE        |
    # |---------|------------------------------------------|------------------------------|
    # |         |                                          |                              |
    # | 2 bytes |  66 NOP                                  |  66 90H                      |
    # | 3 bytes |  NOP DWORD ptr [EAX]                     |  0F 1F 00H                   |
    # | 4 bytes |  NOP DWORD ptr [EAX + 00H]               |  0F 1F 40 00H                |
    # | 5 bytes |  NOP DWORD ptr [EAX + EAX*1 + 00H        |  0F 1F 44 00 00H             |
    # | 6 bytes |  66 NOP DWORD ptr [EAX + EAX*1 + 00H     |  66 0F 1F 44 00 00H          |
    # | 7 bytes |  NOP DWORD ptr [EAX + 00000000 H         |  0F 1F 80 00 00 00 00H       |
    # | 8 bytes |  NOP DWORD ptr [EAX + EAX*1 + 00000000H  |  0F 1F 84 00 00 00 00 00H    |
    # | 9 bytes |  66 NOP DWORD ptr [EAX + EAX*1 00000000H |  66 0F 1F 84 00 00 00 00 00H |

    nops = [
        ['90'],                                        # nop
        ['50','58'],                                   # push eax; pop eax
        ['66','90'],                                   # 2 bytes, 0x66; NOP *
        ['0f','1f','00'],                              # 3 bytes, NOP DWORD ptr [EAX]
        ['0f','1f','40','00'],                         # 4 bytes, NOP DWORD ptr [EAX + 00H]
        ['0f','1f','44','00','00'],                    # 5 bytes, 66 NOP DWORD ptr [EAX + EAX*1 + 00H 
        ['66','0f','1f','44','00','00'],               # 6 bytes, NOP DWORD ptr [EAX + EAX*1 + 00H
        ['0f','1f','80','00','00','00','00'],          # 7 bytes, NOP DWORD ptr [EAX + EAX*1 + 00000000H 
        ['0f','1f','84','00','00','00','00','00'],     # 8 bytes, NOP DWORD ptr [EAX + EAX*1 + 00000000H
        ['66','0f','1f','84','00','00','00','00','00'] # 9 bytes, 66 NOP DWORD ptr [EAX + EAX*1 00000000H
    ]

    length = random.randint(5,20)
    nopsled = ""

    for i in range(length):
        nopsled += "\\x" + "\\x".join(random.choice(nops))
    return(nopsled)


###################
# Profile Functions
def get_sleeptime():
    # Return random sleep in milliseconds
    low = 60 * 1000 # 1 minute
    high = 120 * 1000 # 2 minute
    return str(random.randint(low,high))

def get_jitter():
    # Return random jitter
    low = 33
    high = 49
    return str(random.randint(low,high))

def get_datajitter():
    # Return random data jitter
    low = 100
    high = 300
    return str(random.randint(low,high))

def get_useragent():
    # Return random User-Agent string from the random_user_agent module
    # Set Filter Parameters
    software_names    = [SoftwareName.CHROME.value, SoftwareName.CHROMIUM.value, SoftwareName.EDGE.value, SoftwareName.FIREFOX.value]
    operating_systems = [OperatingSystem.WINDOWS.value, OperatingSystem.LINUX.value, OperatingSystem.MAC.value]   
    hardware_type     = [HardwareType.COMPUTER.value]
    software_type     = [SoftwareType.WEB_BROWSER.value]
    popularity        = [Popularity.POPULAR.value, Popularity.COMMON.value]
    user_agent_rotator = UserAgent(software_names=software_names, operating_systems=operating_systems, hardware_type=hardware_type, software_type=software_type, popularity=popularity, limit=500)
    # Get Random User Agent String.
    user_agent = user_agent_rotator.get_random_user_agent()
    return user_agent

def get_https_certificate_c():
    # Certificate C value
    c = ["AF", "AX", "AL", "DZ", "AS", "AD", "AO", "AI", "AQ", "AG", "AR",
    "AM", "AW", "AU", "AT", "AZ", "BS", "BH", "BD", "BB", "BY", "BE",
    "BZ", "BJ", "BM", "BT", "BO", "BQ", "BA", "BW", "BV", "BR", "IO",
    "BN", "BG", "BF", "BI", "CV", "KH", "CM", "CA", "KY", "CF", "TD",
    "CL", "CN", "CX", "CC", "CO", "KM", "CG", "CD", "CK", "CR", "CI",
    "HR", "CU", "CW", "CY", "CZ", "DK", "DJ", "DM", "DO", "EC", "EG",
    "SV", "GQ", "ER", "EE", "ET", "FK", "FO", "FJ", "FI", "FR", "GF",
    "PF", "TF", "GA", "GM", "GE", "DE", "GH", "GI", "GR", "GL", "GD",
    "GP", "GU", "GT", "GG", "GN", "GW", "GY", "HT", "HM", "VA", "HN",
    "HK", "HU", "IS", "IN", "ID", "IR", "IQ", "IE", "IM", "IL", "IT",
    "JM", "JP", "JE", "JO", "KZ", "KE", "KI", "KP", "KR", "KW", "KG",
    "LA", "LV", "LB", "LS", "LR", "LY", "LI", "LT", "LU", "MO", "MK",
    "MG", "MW", "MY", "MV", "ML", "MT", "MH", "MQ", "MR", "MU", "YT",
    "MX", "FM", "MD", "MC", "MN", "ME", "MS", "MA", "MZ", "MM", "NA",
    "NR", "NP", "NL", "NC", "NZ", "NI", "NE", "NG", "NU", "NF", "MP",
    "NO", "OM", "PK", "PW", "PS", "PA", "PG", "PY", "PE", "PH", "PN",
    "PL", "PT", "PR", "QA", "RE", "RO", "RU", "RW", "BL", "SH", "KN",
    "LC", "MF", "PM", "VC", "WS", "SM", "ST", "SA", "SN", "RS", "SC",
    "SL", "SG", "SX", "SK", "SI", "SB", "SO", "ZA", "GS", "SS", "ES",
    "LK", "SD", "SR", "SJ", "SZ", "SE", "CH", "SY", "TW", "TJ", "TZ",
    "TH", "TL", "TG", "TK", "TO", "TT", "TN", "TR", "TM", "TC", "TV",
    "UG", "UA", "AE", "GB", "US", "UM", "UY", "UZ", "VU", "VE", "VN",
    "VG", "VI", "WF", "EH", "YE", "ZM", "ZW"]

    return random.choice(c)

def get_https_certificate_cn():
    # Certificate CN value
    return get_random_object() + random.choice([".net",".com",".org"])

def get_https_certificate_o():
    # Certificate O value
    return get_random_object()

def get_https_certificate_ou():
    # Certificate OU value
    return get_random_object() + " " + random.choice(["sales", "operations", "legal", "IT","corp"])

def get_tcpport():
    # randdom tcp_port between 1024-60000 (excludes 4000's)
    return str(random.choice((list(range(1024,3999))+list(range(5000,60000)))))

def get_tcp_frame_header():
    # Value to Prepend header to TCP Beacon messages
    length = random.randint(5,35)
    result = get_random_bytearry(length)
    return result

def get_pipename():
    # Name of pipe. Each # is replaced with a random hex value.
    names =  ['ProtectionManager_' + get_random_string(4) + '_##', 'Winsock2\\\\CatalogChangeListener-' + get_random_string(4) + '###-1', 'Spool\\\\pipe_' + get_random_string(4) + '_##', 'WkSvcPipeMgr_' + get_random_string(4) + '##', 'NetClient_' + get_random_string(4) + '##', 'RPC_' + get_random_string(4) + '##','WiFiNetMgr' + get_random_string(4) + '_##','AuthPipe' + get_random_string(4) + '_##']
    return random.choice(names)

def get_smb_frame_header():
    # Prepend header to SMB Beacon messages
    length = random.randint(5,35)
    result = get_random_bytearry(length)
    return result

def get_dns_dnsidle():
    # dns_idle any valid IP address not starting with 0, 10, 172, 192 or 255
    ip_num = list(range(1,9)) + list(range(11,171)) + list(range(173,191)) + list(range(193,254))
    dns_idle = ".".join(map(str, (random.choice(ip_num) for _ in range(4))))   
    return dns_idle

def get_dns_maxtxt():
    #Maximum length of DNS TXT responses for tasks
    return str(random.randint(240,254))

def get_dns_sleep():
    # Force a sleep prior to each individual DNS request. (in milliseconds)
    # Long sleeps can cause trouble with DNS
    return str(random.randint(1,100))

def get_dns_ttl():
    # TTL for DNS replies
    return str(random.randint(1,5))

def get_dns_maxdns():
    # Maximum length of hostname when uploading data over DNS (0-255)
    return str(random.randint(240,254))

def get_dns_host():
    # Random dns host using this format string.string.
    # This must be lowercase
    length = random.randint(1,7)
    return get_random_alphanum(length).lower() + "."

def get_ssh_banner():
    # Return random SSH banner (not guaranteed to real)
    return "SSH-2.0-OpenSSH_" + str(random.randint(4,9)) + "." + str(random.randint(1,9)) + "p" + str(random.randint(0,9)) + " " + str(random.choice(["Debian","Linux","RedHat","CentOS","Ubuntu"]))

def get_http_server_headers():
    # Header: Server
    servers = ['Apache','nginx', 'ESF','cloudflare','gsw','CloudFront', 'Node.js','Microsoft-IIS/10.0','AkamaiGHost','Google Frontend']
    return random.choice(servers)

def get_http_server_contenttype():
    # 
    contenttypes = ["application/javascript","plain/text","application/json"]
    return '"Content-Type" "' + random.choice(contenttypes) + '; charset=utf-8"'

def get_post_ex_spawnto_x86():
    targets = ['svchost.exe -k netsvc','svchost.exe -k wksvc','Locator.exe','systray.exe','WUAUCLT.exe','w32tm.exe','dllhost.exe -o enable','DevicePairingWizard.exe','getmac.exe /V','grpconv.exe','EhStorAuthn.exe','dns-sd.exe']
    target = random.choice(targets)
    return '%windir%\\\\syswow64\\\\' + target

def get_post_ex_spawnto_x64():
    targets = ['svchost.exe -k netsvc','svchost.exe -k wksvc','Locator.exe','systray.exe','WUAUCLT.exe','w32tm.exe','dllhost.exe -o enable','DevicePairingWizard.exe','getmac.exe /V','grpconv.exe','EhStorAuthn.exe','dns-sd.exe']
    target = random.choice(targets)
    return '%windir%\\\\sysnative\\\\' + target

def get_post_ex_pipename_list():
    names =  'ProtectionManager_##, Winsock2\\\\CatalogChangeListener-##-##, Spool\\\\pipe_##, WkSvcPipeMgr_##, NetClient_##, RPC_##, WiFiNetMgr_##, AuthPipeD_##'
    return names

def get_stage_allocator():
    # Set how Beacon's Reflective Loader allocates memory for the agent. Options are: HeapAlloc, MapViewOfFile, and VirtualAlloc.
    options = ["VirtualAlloc","HeapAlloc","MapViewOfFile"]
    allocator = random.choice(options)
    rwx = "false"
    if allocator == "HeapAlloc":
        rwx = "true"
    # rdll_use_syscalls is only valid when rdll_loader is PrependLoader and the
    # allocator is VirtualAlloc or MapViewOfFile. Our template always sets
    # rdll_loader to PrependLoader, so we condition this solely on the allocator.
    rdll_use_syscalls = "true" if allocator in ["VirtualAlloc", "MapViewOfFile"] else "false"
    lines = [
        f'    set allocator         "{allocator}";',
        f'    set userwx            "{rwx}";',
        f'    set rdll_use_syscalls "{rdll_use_syscalls}";',
    ]

    # Drip-loading is only honored when allocator is VirtualAlloc
    if allocator == "VirtualAlloc":
        if random.choice([True, False]):
            delay = random.randint(50, 250)
            lines.append('    set rdll_use_driploading "true";')
            lines.append(f'    set rdll_dripload_delay "{delay}";')

    allocator_settings = "\n".join(lines)
    return allocator_settings

def get_stage_magic_pe():
    # Override the PE character marker used by Beacon's Reflective Loader with another value.
    return get_random_string(2)

def get_stage_data_store_size():
    # Beacon Data Store enables an operator to store Beacon Object Files (BOFs) and .NET assemblies in Beacon's memory.
    return str(random.choice(range(16, 65, 16)))

def get_stage_syscall_method():
    # System call method to be used at execution time. Options are: None, Direct, or Indirect.
    return random.choice(["None", "Direct", "Indirect"])


def get_stage_beacon_gate():
    # Configure BeaconGate APIs that will be proxied via the Sleepmask.
    # When this returns an empty string, no beacon_gate block will be emitted.
    #
    # References:
    # https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-gate.htm
    #
    # Supported groups:
    # - Comms   : InternetOpenA, InternetConnectA (HTTP(S) WinInet Beacon only)
    # - Core    : Core Beacon API set (VirtualAlloc, OpenProcess, WriteProcessMemory, etc.)
    # - Cleanup : ExitThread (when Exit Function is set to Thread and module_x* is not used)
    # - All     : Comms + Core + Cleanup
    #
    # It is also possible to proxy specific functions from the supported set, which is what
    # this helper does when the "custom" mode is selected.

    strategies = ["none", "comms", "core", "cleanup", "all", "custom"]
    choice = random.choice(strategies)

    # All supported APIs that may be forwarded via BeaconGate
    comms_apis = ["InternetOpenA", "InternetConnectA"]
    core_apis = [
        "CloseHandle",
        "CreateFileMappingA",
        "CreateRemoteThread",
        "CreateThread",
        "DuplicateHandle",
        "GetThreadContext",
        "MapViewOfFile",
        "OpenProcess",
        "OpenThread",
        "ReadProcessMemory",
        "ResumeThread",
        "SetThreadContext",
        "UnMapViewOfFile",
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualFree",
        "VirtualProtect",
        "VirtualProtectEx",
        "VirtualQuery",
        "WriteProcessMemory",
    ]
    cleanup_apis = ["ExitThread"]

    # "none" means do not emit a beacon_gate block at all
    if choice == "none":
        return ""

    apis = []

    if choice in ("comms", "all"):
        apis.extend(comms_apis)

    if choice in ("core", "all"):
        apis.extend(core_apis)

    if choice in ("cleanup", "all"):
        apis.extend(cleanup_apis)

    if choice == "custom":
        all_apis = list(set(comms_apis + core_apis + cleanup_apis))
        count = random.randint(2, min(6, len(all_apis)))
        apis = random.sample(all_apis, count)

    # De-duplicate while preserving order
    seen = set()
    unique_apis = []
    for api in apis:
        if api not in seen:
            seen.add(api)
            unique_apis.append(api)

    if not unique_apis:
        return ""

    lines = ["beacon_gate {"]
    for api in unique_apis:
        lines.append(f"      {api};")
    lines.append("    }")

    return "\n".join(lines)


def get_stage_eaf_bypass():
    # EAF bypass is only enabled and meaningful when rdll_loader is PrependLoader.
    # Our template always uses PrependLoader, so here we simply randomize whether
    # to enable the bypass.
    return random.choice(["true", "false"])


def get_stage_transform_obfuscate():
    # Build a transform-obfuscate block to perform additional transformations on
    # Beacon's DLL payload. This is only supported when rdll_loader is set to
    # PrependLoader, which our template enforces.
    #
    # Supported transformations:
    #   - base64  : optional key length (8-2048)
    #   - lznt1   : optional key length (8-2048)
    #   - rc4     : required key length (8-128, must not exceed 128)
    #   - xor     : required key length (8-2048)
    #
    # Transformations are applied in the order specified here; PrependLoader will
    # process them in reverse to recover the original DLL payload.

    transforms = ["lznt1", "rc4", "xor"]

    def render_transform(name: str) -> str:
        if name == "rc4":
            # RC4 key length is limited to 128 characters
            key_len = random.randint(8, 128)
            return f'        rc4 "{key_len}";'
        elif name == "xor":
            key_len = random.randint(8, 64)
            return f'        xor "{key_len}";'
        elif name == "lznt1":
            return "        lznt1;"
        else:
            return ""
    random.shuffle(transforms)
    lines = ["transform-obfuscate {"]
    for t in transforms:
        lines.append(render_transform(t))
    lines.append("    }")

    return "\n".join(lines)

def get_stage_magic_mz_86():
# References:
# https://www.redteam.cafe/red-team/shellcode-injection/magic_mz_x86-and-magic_mz_x64
# https://www.cobaltstrike.com/help-malleable-postex
# https://www.cs.uaf.edu/2015/fall/cs301/lecture/09_16_stack.html

    codes = [
    'H@KC', # ASM = dec eax, inc eax, dec ebx, inc ebx
    'KCKC', # ASM = dec ebx, inc ebx, dec ebx, inc ebx
    '@H@H', # ASM = inc eax, dec eax, inc eax, dec eax
    ']U]U', # ASM = pop ebp, push ebp, pop ebp, push ebp 
    'MEME'  # ASM = inc ebp, dec ebp, inc ebp, dec ebp 
    ]

    return random.choice(codes)


def get_stage_magic_mz_64():
# References:
# https://www.redteam.cafe/red-team/shellcode-injection/magic_mz_x86-and-magic_mz_x64
# https://www.cobaltstrike.com/help-malleable-postex
# https://www.cs.uaf.edu/2015/fall/cs301/lecture/09_16_stack.html

    codes = [
    'AXAP', # ASM = pop r8, push r8
    'AYAQ', # ASM = pop r9, push r9
    'AZAR', # ASM = pop r10, push r10
    '^V',   # ASM = pop rsi, push rsi
    'A[AS' # ASM = pop r11, push r11
    ]

    return random.choice(codes)


def get_stage_compile_time():
    month  = random.choice(['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'])
    day    = str(random.randint(1,30)).zfill(2)
    year   = str(random.choice(range(2005,2022)))
    hour   = str(random.randint(1,23)).zfill(2)
    minute = str(random.randint(1,59)).zfill(2) 
    second = str(random.randint(1,50)).zfill(2) 
    return day + " " + month + " " + year + " " + hour + ":" + minute + ":" + second

def get_stage_entry_point():
    # The EntryPoint value in Beacon's PE header
    low = 300000
    high = 800000
    return str(random.randint(low,high))

def get_stage_image_size_x86():
    # SizeOfImage value in x86 Beacon's PE header.
    low = 512001
    high = 576000
    return str(random.randint(low,high))

def get_stage_image_size_x64():
    # SizeOfImage value in x64 Beacon's PE header.
    low = 512001
    high = 576000
    return str(random.randint(low,high))

def get_stage_name():
    # The Exported name of the Beacon DLL
    return get_random_object() + ".dll"


def get_stage_rich_header():
    # https://blog.cobaltstrike.com/2018/04/09/cobalt-strike-3-11-the-snake-that-eats-its-tail/
    # https://securelist.com/the-devils-in-the-rich-header/84348/
    # |        |                        |                    |                             |
    # | ------ | ---------------------- | ------------------ | --------------------------- |
    # | Offset | First value            | Second value       | Description                 |
    # | 00     | 44 61 6E 53 (“DanS”)   | 00 00 00 00        | Beginning of the header     |
    # | 08     | 00 00 00 00            | 00 00 00 00        | Empty record                |
    # | 10     | Tool id, build version | Number of items    | Bill of materials record #1 |
    # | …      |                        |                    |                             |
    # | …      | 52 69 63 68 “Rich”     | Checksum / XOR key | End of the header           |


    DanS = "\\x" + "\\x".join(["44","61","61","53"])
    DansS_second = "\\x" + "\\x".join(["00","00","00","00"])
    offset08 = "\\x" + "\\x".join(["00","00","00","00"])
    offset08_second = "\\x" + "\\x".join(["00","00","00","00"])
    content = get_random_bytearry(72) # 72 bytes
    Rich = "\\x" + "\\x".join(["52","69","63","68"])
    End1 = "\\x" + "\\x".join(["7a","f9","90","26"])
    End2 = "\\x" + "\\x".join(["00","00","00","00"])
    End3 = "\\x" + "\\x".join(["00","00","00","00"])
    End4 = "\\x" + "\\x".join(["00","00","00","00"])
    #rich_header = str(DanS) + DansS_second + offset08 + offset08_second + content + Rich + End1 + End2
    rich_header = str(DanS) + DansS_second + offset08 + offset08_second + content + Rich + End1 + End2 + End3 + End4
    return rich_header

def get_process_inject_allocator():
    # The preferred method to allocate memory in the remote process. Specify VirtualAllocEx or NtMapViewOfSection. The NtMapViewOfSection option is for same-architecture injection only. VirtualAllocEx is always used for cross-arch memory allocations.
    options = ['VirtualAllocEx', 'NtMapViewOfSection']
    return random.choice(options)

def get_process_inject_bof_allocator():
    # The preferred method to allocate memory in the current process to execute a BOF. Specify VirtualAlloc, MapViewOfFile, or HeapAlloc. 
    options = ['VirtualAlloc', 'MapViewOfFile','HeapAlloc']
    return random.choice(options)

def get_process_inject_min_alloc():
    # Minimum amount of memory to request for injected content
    low = 4096
    high = 20480
    return str(random.randint(low,high))


def get_process_inject_use_driploading():
    # Control whether process injection uses drip-loading (small chunks with
    # delays between operations) to reduce large allocation heuristics.
    choices = ["true", "false"]
    return random.choice(choices)


def get_process_inject_dripload_delay():
    # Delay (in milliseconds) between drip-loading steps for process injection.
    # Keep within a few hundred milliseconds to avoid excessive startup delay.
    return str(random.randint(50, 250))

def get_process_inject_execute():
    # execute block controls the methods Beacon will use when it needs to inject code into a process. 
    execute_string = '''
        CreateThread "ntdll!RtlUserThreadStart+0x{0}";
        CreateThread;
        NtQueueApcThread-s;
        CreateRemoteThread;
        RtlCreateUserThread; 
    '''.format(random.randint(42,1000))
    return execute_string

def get_http_config_headers():
    # Header: Server
    servers = ['Apache','nginx', 'ESF','cloudflare','gsw','CloundFront', 'Node.js','Microsoft-IIS/10.0','AkamaiGHost','Google Frontend']
    return random.choice(servers)

def get_http_client_metadata_cookie():
    cookie_prefixes = [
                        "_" + get_random_string(2) + "id", 
                        'SESSIONID_' + get_random_alphanum(random.randint(8,32)), 
                        'secure_id_' + get_random_alphanum(random.randint(8,32)), 
                        'auth_token' + get_random_alphanum(4), 
                        'affiliate_id_' + get_random_alphanum(16),
                        get_random_alphanum(random.randint(2,4)) +"_" + get_random_alphanum(32)
                      ]
    cookie = random.choice(cookie_prefixes) + "="
    return cookie

def get_http_post_client_id_parameter():
    return "_" + get_random_string(8)