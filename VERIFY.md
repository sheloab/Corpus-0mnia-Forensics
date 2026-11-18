# Verify a C0F kit before use

Trust comes from **outside** the kit. C0F has an open license: anyone may build and sign their own copy,
and a replaced kit can carry its own public key and an altered script. Only the official public key,
taken from your SOP or this page, proves that a kit is an official C0F release.

    Official C0F release key (minisign):
    RWTFlf0U9/S2PXk4OI50uQVSJDMd8eMj4fzXLKRv9IpU8ux5DvRQpr5p
    key id 3DB6F4F714FD95C5

Write this key into your SOP once. Compare it every time; do not copy it from a downloaded kit.

Use a `minisign` you trust: your OS packages (`apt install minisign`, `dnf install minisign`,
`brew install minisign`, `scoop install minisign`) or https://github.com/jedisct1/minisign/releases.
Never verify with the `minisign` inside the kit, and never verify on the server you examine.

## 1. Release download (before extracting)

Files: `C0F-<version>.tar.gz`, `RELEASE-SHA256SUMS.txt`, `RELEASE-SHA256SUMS.txt.minisig`.

Linux / macOS:

    minisign -Vm RELEASE-SHA256SUMS.txt -P RWTFlf0U9/S2PXk4OI50uQVSJDMd8eMj4fzXLKRv9IpU8ux5DvRQpr5p
    sha256sum -c --ignore-missing RELEASE-SHA256SUMS.txt          # macOS: shasum -a 256 -c

Windows (PowerShell):

    minisign.exe -Vm RELEASE-SHA256SUMS.txt -P RWTFlf0U9/S2PXk4OI50uQVSJDMd8eMj4fzXLKRv9IpU8ux5DvRQpr5p
    (Get-FileHash C0F-<version>.tar.gz -Algorithm SHA256).Hash     # must equal the line in RELEASE-SHA256SUMS.txt

Expected: `Signature and comment signature verified`, trusted comment `C0F <version> - official release files`,
and the archive hash matching.

## 2. Extracted kit (or a kit received from a colleague)

    cd C0F-KIT
    minisign -Vm SHA256SUMS -P RWTFlf0U9/S2PXk4OI50uQVSJDMd8eMj4fzXLKRv9IpU8ux5DvRQpr5p
    sha256sum -c SHA256SUMS                      # every line OK

Expected trusted comment: `C0F <version> - official release`. Record the SHA-256 of `SHA256SUMS`
in your case notes.

## 3. At every start (automatic)

C0F checks the signature with the `minisign.pub` inside the kit plus the SHA-256 of every file, and prints:

    public key       : <key used>   (compare with the key in your SOP)
    release key      : official C0F release key            <- or: NOT the official C0F release key

`NOT the official C0F release key` means a private build or a replaced kit: stop and investigate.
This self-check catches damaged or partly modified kits. It cannot replace steps 1-2, because a fully
replaced kit controls its own check.

If the signature fails or a core file is modified, C0F stops before collecting (see section 4 of the
kit `README.txt`).
