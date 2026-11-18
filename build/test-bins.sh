#!/bin/sh
# Smoke-run every kit binary. Usage: test-bins.sh <dir> [emulator]. Prints PASS/FAIL per binary.
D=$1; E=$2; MGC=$3; pass=0; fail=0
run(){ out=$(timeout 20 $E "$@" 2>&1 </dev/null); rc=$?; echo "$rc|$(echo "$out" | head -1 | cut -c1-70)"; }
bad(){ echo "$1" | grep -qiE 'exec format|illegal instruction|segmentation|bus error|not found|cannot execute|unsupported|core dumped|Aborted'; }
for f in $(cd $D && find . -type f | sort); do p=$D/${f#./}; n=$(basename $f)
  case $n in
    busybox) r=$(run $p uname -m) ;;
    xtables-legacy-multi) r=$(run $p iptables-save -V) ;;
    xtables-nft-multi) r=$(run $p iptables-nft-save -V) ;;
    lsattr|ipset) r=$(run $p -V); [ $n = ipset ] && r=$(run $p version) ;;
    getcap) r=$(run $p $p) ;;
    lsof|minisign) r=$(run $p -v) ;;
    file) r=$(run $p -m $MGC $p) ;;
    dmidecode|nft|tcpdump) r=$(run $p --version) ;;
    ip|ss|bridge) r=$(run $p -V) ;;
    chkrootkit) continue ;;
    chkproc|chkdirs|chkutmp|chklastlog|chkwtmp|check_wtmpx|ifpromisc) r=$(run $p -h); r="0|${r#*|}" ;;
    strings-static) r=$(run $p $p); r="0|${r#*|}" ;;
    sqlite3) r=$(echo 'select sqlite_version();' | timeout 20 $E $p 2>&1 | head -1); r="0|$r" ;;
    c0f-*) r=$(run $p -V) ;;
    kubectl) r=$(run $p version --client) ;;
    7zzs) r=$(run $p i); r="0|$(echo "${r#*|}")" ;;
    *) r=$(run $p --version) ;;
  esac
  rc=${r%%|*}; txt=${r#*|}
  if bad "$txt" || { [ "$rc" != 0 ] && [ -z "$txt" ]; } || [ "$rc" = 124 ]; then echo "FAIL $n rc=$rc: $txt"; fail=$((fail+1)); else pass=$((pass+1)); fi
done
echo "RESULT pass=$pass fail=$fail"
