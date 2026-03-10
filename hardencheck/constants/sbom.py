# ============================================================================
# SBOM: CPE/PURL mapping for known IoT firmware components
# Format: binary_name -> (vendor, product, cpe_prefix, purl_type)
# CPE 2.3: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
# ============================================================================
CPE_COMPONENT_MAP = {
    # Core system
    "busybox":       ("busybox", "busybox", "a", "generic"),
    "libc.so":       ("gnu", "glibc", "a", "generic"),
    "libc-":         ("gnu", "glibc", "a", "generic"),
    "ld-linux":      ("gnu", "glibc", "a", "generic"),
    "ld-musl":       ("musl-libc", "musl", "a", "generic"),
    "libuClibc":     ("uclibc", "uclibc", "a", "generic"),

    # SSL/TLS
    "libssl":        ("openssl", "openssl", "a", "generic"),
    "libcrypto":     ("openssl", "openssl", "a", "generic"),
    "openssl":       ("openssl", "openssl", "a", "generic"),
    "libwolfssl":    ("wolfssl", "wolfssl", "a", "generic"),
    "libmbedtls":    ("arm", "mbed_tls", "a", "generic"),
    "libmbedcrypto": ("arm", "mbed_tls", "a", "generic"),
    "libgnutls":     ("gnu", "gnutls", "a", "generic"),

    # Crypto
    "libsodium":     ("libsodium_project", "libsodium", "a", "generic"),
    "libgcrypt":     ("gnupg", "libgcrypt", "a", "generic"),
    "libnettle":     ("gnu", "nettle", "a", "generic"),

    # Web servers
    "nginx":         ("f5", "nginx", "a", "generic"),
    "lighttpd":      ("lighttpd", "lighttpd", "a", "generic"),
    "httpd":         ("apache", "http_server", "a", "generic"),
    "apache2":       ("apache", "http_server", "a", "generic"),
    "uhttpd":        ("openwrt", "uhttpd", "a", "generic"),
    "goahead":       ("embedthis", "goahead", "a", "generic"),
    "boa":           ("boa", "boa_web_server", "a", "generic"),
    "thttpd":        ("acme", "thttpd", "a", "generic"),
    "mini_httpd":    ("acme", "mini_httpd", "a", "generic"),
    "mongoose":      ("cesanta", "mongoose", "a", "generic"),

    # SSH
    "dropbear":      ("dropbear_ssh_project", "dropbear_ssh", "a", "generic"),
    "sshd":          ("openbsd", "openssh", "a", "generic"),

    # DNS
    "dnsmasq":       ("thekelleys", "dnsmasq", "a", "generic"),
    "named":         ("isc", "bind", "a", "generic"),
    "unbound":       ("nlnetlabs", "unbound", "a", "generic"),

    # Network services
    "hostapd":       ("w1.fi", "hostapd", "a", "generic"),
    "wpa_supplicant":("w1.fi", "wpa_supplicant", "a", "generic"),
    "openvpn":       ("openvpn", "openvpn", "a", "generic"),
    "pppd":          ("samba", "ppp", "a", "generic"),
    "mosquitto":     ("eclipse", "mosquitto", "a", "generic"),
    "avahi-daemon":  ("avahi", "avahi", "a", "generic"),

    # SMB/NFS
    "smbd":          ("samba", "samba", "a", "generic"),
    "nmbd":          ("samba", "samba", "a", "generic"),
    "nfsd":          ("linux", "nfs-utils", "a", "generic"),

    # FTP
    "vsftpd":        ("vsftpd_project", "vsftpd", "a", "generic"),
    "proftpd":       ("proftpd", "proftpd", "a", "generic"),

    # SNMP
    "snmpd":         ("net-snmp", "net-snmp", "a", "generic"),

    # Misc libraries
    "libz.so":       ("zlib", "zlib", "a", "generic"),
    "libcurl":       ("haxx", "curl", "a", "generic"),
    "curl":          ("haxx", "curl", "a", "generic"),
    "wget":          ("gnu", "wget", "a", "generic"),
    "libjson-c":     ("json-c_project", "json-c", "a", "generic"),
    "libxml2":       ("xmlsoft", "libxml2", "a", "generic"),
    "libsqlite":     ("sqlite", "sqlite", "a", "generic"),
    "sqlite3":       ("sqlite", "sqlite", "a", "generic"),
    "libpcre":       ("pcre", "pcre", "a", "generic"),
    "libexpat":      ("libexpat_project", "libexpat", "a", "generic"),
    "libpng":        ("libpng", "libpng", "a", "generic"),
    "libjpeg":       ("ijg", "libjpeg", "a", "generic"),
    "libdbus":       ("freedesktop", "dbus", "a", "generic"),
    "libubus":       ("openwrt", "ubus", "a", "generic"),
    "libubox":       ("openwrt", "libubox", "a", "generic"),
    "libuci":        ("openwrt", "uci", "a", "generic"),
    "libblkid":      ("kernel", "util-linux", "a", "generic"),
    "libuuid":       ("kernel", "util-linux", "a", "generic"),
    "libpthread":    ("gnu", "glibc", "a", "generic"),
    "librt":         ("gnu", "glibc", "a", "generic"),
    "libdl":         ("gnu", "glibc", "a", "generic"),
    "libm":          ("gnu", "glibc", "a", "generic"),
    "libstdc++":     ("gnu", "gcc", "a", "generic"),
    "libgcc_s":      ("gnu", "gcc", "a", "generic"),
    "libnl":         ("libnl_project", "libnl", "a", "generic"),
    "libiwinfo":     ("openwrt", "iwinfo", "a", "generic"),
    "libnfnetlink":  ("netfilter", "libnetfilter", "a", "generic"),
    "libiptc":       ("netfilter", "iptables", "a", "generic"),
    "iptables":      ("netfilter", "iptables", "a", "generic"),
    "ip6tables":     ("netfilter", "iptables", "a", "generic"),
    "nftables":      ("netfilter", "nftables", "a", "generic"),
    "libreadline":   ("gnu", "readline", "a", "generic"),
    "libncurses":    ("gnu", "ncurses", "a", "generic"),

    # IoT / MQTT / CoAP
    "libcoap":       ("libcoap", "libcoap", "a", "generic"),
    "libmosquitto":  ("eclipse", "mosquitto", "a", "generic"),
    "libpaho":       ("eclipse", "paho_mqtt", "a", "generic"),

    # Containers / runtime
    "containerd":    ("linuxfoundation", "containerd", "a", "generic"),
    "dockerd":       ("docker", "docker", "a", "generic"),
    "runc":          ("opencontainers", "runc", "a", "generic"),

    # Kernel
    "vmlinux":       ("linux", "linux_kernel", "o", "generic"),
    "vmlinuz":       ("linux", "linux_kernel", "o", "generic"),
    "zImage":        ("linux", "linux_kernel", "o", "generic"),
    "uImage":        ("linux", "linux_kernel", "o", "generic"),
    "bzImage":       ("linux", "linux_kernel", "o", "generic"),

    # UPnP / TR-069
    "miniupnpd":     ("miniupnp_project", "miniupnpd", "a", "generic"),
    "cwmpd":         ("cwmp", "cwmpd", "a", "generic"),
}

# License hints from binary/package names
LICENSE_HINTS = {
    "busybox": "GPL-2.0-only",
    "glibc": "LGPL-2.1-or-later",
    "musl": "MIT",
    "uclibc": "LGPL-2.1-or-later",
    "openssl": "Apache-2.0",
    "wolfssl": "GPL-2.0-or-later",
    "mbed_tls": "Apache-2.0",
    "gnutls": "LGPL-2.1-or-later",
    "nginx": "BSD-2-Clause",
    "lighttpd": "BSD-3-Clause",
    "dropbear_ssh": "MIT",
    "openssh": "BSD-2-Clause",
    "dnsmasq": "GPL-2.0-only",
    "curl": "curl",
    "zlib": "Zlib",
    "sqlite": "blessing",
    "libxml2": "MIT",
    "libpng": "Libpng",
    "samba": "GPL-3.0-or-later",
    "mosquitto": "EPL-2.0",
    "openvpn": "GPL-2.0-only",
    "hostapd": "BSD-3-Clause",
    "wpa_supplicant": "BSD-3-Clause",
    "iptables": "GPL-2.0-or-later",
    "linux_kernel": "GPL-2.0-only",
    "util-linux": "GPL-2.0-or-later",
    "gcc": "GPL-3.0-or-later",
    "readline": "GPL-3.0-or-later",
    "ncurses": "MIT",
    "net-snmp": "BSD-3-Clause",
    "dbus": "AFL-2.1 OR GPL-2.0-or-later",
    "json-c": "MIT",
}
