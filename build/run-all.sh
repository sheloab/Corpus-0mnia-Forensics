#!/bin/sh
# Build all three architectures one after another in throw-away offline containers.
# Each run executes a frozen SNAPSHOT of build-arch.sh, so editing the script during a build cannot affect it.
cd "$(dirname "$0")/.."
mkdir -p build/logs build/out build/zig-cache build/snap
for A in x86_64 aarch64 armv7; do
  cp build/build-arch.sh build/snap/build-arch.$A.sh; chmod 755 build/snap/build-arch.$A.sh
  echo "START $A $(date -u +%FT%TZ) script-sha256=$(sha256sum build/snap/build-arch.$A.sh | cut -c1-16)"
  nice -n 10 sudo -n docker run --rm --name c0f-build-$A --network none -v "$PWD":/w c0f-build:1 /w/build/snap/build-arch.$A.sh $A
  echo "END $A rc=$? $(date -u +%FT%TZ)"
done
echo ALL-DONE
