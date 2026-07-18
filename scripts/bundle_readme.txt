binderdump — grab-and-go bundle

Install (Linux host with Wireshark + adb):

    ./install.sh

This installs the dissector, the AIDL/HIDL corpus, the column profile, the
live-capture extcap, and the Android capture binary into your personal
Wireshark directories. Wireshark must already be installed (the installer
picks the bundled dissector matching your Wireshark version).

Then, in Wireshark, pick an "Android binder (<serial>)" interface for live
capture over adb, or open a captured .pcapng and switch to the "binderdump"
profile (bottom-right of the status bar) for the preset columns.

Advanced / custom installs: run ./install_dissector.sh with explicit
--so / --corpus / --profile / --extcap paths. See the project README.

Layout:
    dissector/   dissector .so, one per Wireshark version
    corpus/      aosp/ and native/ method+param decode data
    profile/     Wireshark column profile
    extcap/      live-capture helper
    android/     on-device capture binary + offset_finder
    SHA256SUMS   checksums of this bundle's files
