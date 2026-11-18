# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors

# ======================= D99 custody files =======================
# write_custody_files OUTROOT TMP : manifest.csv, failures.csv, not-collected.csv, tools-used.csv, report.txt, chain-of-custody.txt
write_custody_files() {
  R=$1; W=$2; C="$R/99_custody"; I="$W/items.tsv"; CAT="$KIT/catalog.tsv"
  # 1. union of copy metadata (one row per requested source path), with the item id in front
  : > "$W/copies.tsv"
  for m in "$W"/meta/*.tsv; do [ -f "$m" ] || continue; id=${m##*/}; id=${id%.tsv}
    awk -F'\t' -v id="$id" 'NR>1 && $1!="status" {print id"\t"$0}' "$m" >> "$W/copies.tsv"; done
  # 2. sub-results of FUNC items
  : > "$W/subs.tsv"
  for s in "$W"/sub/*.tsv; do [ -f "$s" ] || continue; id=${s##*/}; id=${id%.tsv}; awk -F'\t' -v id="$id" '{print id"\t"$0}' "$s" >> "$W/subs.tsv"; done
  # 3. failures.csv and not-collected.csv
  awk -F'\t' -v OFS=, 'function q(s){gsub(/"/,"\"\"",s); return "\"" s "\""}
    FILENAME==ARGV[1] && FNR==1 {print "seq,item_id,domain,what,status,reason,exit_code,duration_ms,detail"; next}
    FILENAME==ARGV[1] { if ($8=="FAILED"||$8=="TIMEOUT"||$8=="DENIED") print $1,$2,$3,q($6),$8,$9,$10,$13,q($16); next }
    FILENAME==ARGV[2] { s=$2; if (s!="OK" && s!="EMPTY" && s!="CHANGED_DURING_COPY" && s!="NOT_FOUND" && s !~ /^SKIPPED/) print "-",$1,"-",q($3),s,s,"-","-",q($21); next }
    FILENAME==ARGV[3] { if ($2=="FAILED"||$2=="DENIED"||$2=="TIMEOUT") print "-",$1,"-",q($4),$2,$3,"-","-","" }' "$I" "$W/copies.tsv" "$W/subs.tsv" > "$C/failures.csv"
  awk -F'\t' -v OFS=, 'function q(s){gsub(/"/,"\"\"",s); return "\"" s "\""}
    FILENAME==ARGV[1] && FNR==1 {print "item_id,domain,searched_path_or_command,status,reason,detail"; next}
    FILENAME==ARGV[1] { if ($8=="NOT FOUND"||$8=="SKIPPED"||$8=="EMPTY") print $2,$3,q($6),$8,$9,q($16); next }
    FILENAME==ARGV[2] { if ($2=="NOT_FOUND") print $1,"-",q($3),"NOT FOUND","NOT_FOUND",q($21); else if ($2 ~ /^SKIPPED/) print $1,"-",q($3),"SKIPPED",$2,q($21); next }
    FILENAME==ARGV[3] { if ($2=="NOT FOUND"||$2=="SKIPPED") print $1,"-",q($4),$2,$3,"" }' "$I" "$W/copies.tsv" "$W/subs.tsv" > "$C/not-collected.csv"
  # 4. tools-used.csv
  { echo "tool,origin,path,sha256,self_test,integrity,used_by_items,crashed_in_items"
    awk -F, -v integ="$KIT_INTEGRITY" 'NR>1{ r=$4; i=(r=="OK"||r=="PRESENT")?"VERIFIED":"NOT_USED"; print $1",kit,"$2","$3","r","i",," }' "$W/kit-selftest.csv"
    cat "$W"/srv/*.log 2>/dev/null | sort -u | while read -r p; do
      used=$(grep -lxF "$p" "$W"/srv/*.log | sed 's|.*/||; s|\.log$||' | tr '\n' ' ')
      crashed=$(grep -lF "$p	" "$W"/srv/*.log.crash 2>/dev/null | sed 's|.*/||; s|\.log\.crash$||' | tr '\n' ' ')
      echo "${p##*/},server,$p,$(sha "$p"),-,UNTRUSTED_TOOL,$used,$crashed"; done; } > "$C/tools-used.csv"
  # 5. manifest.csv: every file in the evidence folder with SHA-256 + MD5, linked to its item and source
  c0f-copy -D -R "$R" > "$W/digest.tsv" 2>/dev/null
  awk -F'\t' -v OFS=, -v root="$R" -v name="$NAME" -v doms="$DOMAINS" '
    function q(s){gsub(/"/,"\"\"",s); return "\"" s "\""}
    BEGIN{ n=split(doms,D," "); for(i=1;i<=n;i++){ split(D[i],kv,":"); DIR[kv[1]]=kv[2] } }
    FILENAME==ARGV[1] { if (FNR==1) next; iid[$2]=$2; idom[$2]=$3; iend[$2]=$12; ist[$2]=$8; irs[$2]=$9; iint[$2]=$15; icmd[$2]=$6
                        if ($7!="-" && $4!="COPY") outs[$7]=$2; next }
    FILENAME==ARGV[2] { if ($4!="-") { k=$4; sub(/^\//,"",k); cp[k]=$1; csrc[k]=$3; csha[k]=$20; cm[k]=$14; cc[k]=$15; ca[k]=$13; cb[k]=$16; cu[k]=$8; cg[k]=$9; cmo[k]=$7; cin[k]=$10; cst[k]=$2 } ; next }
    FILENAME==ARGV[3] { if (FNR==1) { print "seq,item_id,domain,method,source,archive_path,size,sha256,md5,src_sha256,orig_mtime,orig_ctime,orig_atime,orig_btime,uid,gid,mode,inode,collected_utc,status,reason,tool_integrity,note"; next }
      if ($4!="f") next
      p=$2; rel=substr(p, length(root)+2); md5=$20; sub(/.*md5=/,"",md5); sub(/;.*/,"",md5)
      id="-"; meth="OTHER"; src="-"; ssha=""; om=oc=oa=ob=ou=og=omo=oin=""; st="OK"; rs="-"
      if (rel in cp) { id=cp[rel]; meth="COPY"; src=csrc[rel]; ssha=csha[rel]; om=cm[rel]; oc=cc[rel]; oa=ca[rel]; ob=cb[rel]; ou=cu[rel]; og=cg[rel]; omo=cmo[rel]; oin=cin[rel]; st=cst[rel] }
      else if (rel in outs) { id=outs[rel]; meth="CAPTURE"; src=icmd[id] }
      else { best=""; for (o in outs) if (index(rel, o "/")==1 && length(o)>length(best)) best=o; if (best!="") { id=outs[best]; meth="CAPTURE"; src=icmd[id] }
             else if (rel ~ /^99_custody\//) { meth="CUSTODY" } else if (rel ~ /\.stderr\.txt$/) { meth="STDERR" } }
      if (rel ~ /\.stderr\.txt$/) meth="STDERR"
      dom=(id in idom)?idom[id]:"-"; ce=(id in iend)?iend[id]:""; ti=(id in iint)?iint[id]:"-"
      seq++; print seq, id, dom, meth, q(src), q(name "/" rel), $5, $19, md5, ssha, om, oc, oa, ob, ou, og, omo, oin, ce, st, rs, ti, q($20) ; next }
    FILENAME==ARGV[4] { if ($2!="OK" && $2!="EMPTY" && $2!="CHANGED_DURING_COPY") { seq++; print seq, $1, (($1 in idom)?idom[$1]:"-"), "NOT_COLLECTED", q($3), "", "", "", "", "", "", "", "", "", "", "", "", "", (($1 in iend)?iend[$1]:""), $2, $2, "-", q($21) } ; next }
    FILENAME==ARGV[5] { if (FNR==1) next; if ($8!="OK" && $8!="EMPTY") { seq++; print seq, $2, $3, "NOT_COLLECTED", q($6), "", "", "", "", "", "", "", "", "", "", "", "", "", $12, $8, $9, $15, q($16) } }
  ' "$I" "$W/copies.tsv" "$W/digest.tsv" "$W/copies.tsv" "$I" > "$C/manifest.csv"
  MAN_SHA=$(sha "$C/manifest.csv"); MAN_MD5=$(md5sum "$C/manifest.csv" | cut -c1-32)
  NFILES=$(awk -F, 'NR>1 && $4!="NOT_COLLECTED"' "$C/manifest.csv" | wc -l); NBYTES=$(awk -F'\t' '$4=="f"{s+=$5} END{printf "%.0f", s}' "$W/digest.tsv")
  # 6. report.txt
  {
    echo "KIT INTEGRITY: $KIT_INTEGRITY${KIT_CHANGED:+ (KIT CHANGED DURING RUN)}    COLLECTION STATUS: $RUN_STATUS"
    echo "Corpus-0mnia Forensics (C0F) $C0F_VERSION - collection report"
    echo "==========================================================================="
    echo "Host            : $HOST (raw hostname: $HOST_RAW)   IP: $HOST_IP"
    echo "Display name    : $DISPLAY_NAME"
    echo "OS              : $OS_NAME (ID=$OS_ID VERSION_ID=$OS_VERSION_ID, profile $OS_PROFILE) kernel $(uname -r) arch $ARCH"
    echo "Case / examiner : $CASE / $EXAMINER"
    echo "Started (UTC)   : $RUN_START_UTC   local: $RUN_START_LOCAL"
    echo "Finished (UTC)  : $RUN_END_UTC   local: $RUN_END_LOCAL"
    echo "Output folder   : $OUTDIR (on the examined system: $( [ "$OUT_EXTERNAL" = YES ] && echo no || echo YES); filesystem $OUT_FSTYPE)"
    echo "Items           : $NITEMS in catalog  | OK $N_OK  EMPTY $N_EMPTY  NOT FOUND $N_NF  SKIPPED/NOT APPLICABLE $N_SKIP (not run for lack of space/interrupted: ${N_NOTRUN:-0})  FAILED $N_FAIL  TIMEOUT $N_TO  DENIED $N_DEN  | warnings $C0F_WARNINGS"
    echo "Evidence files  : $NFILES files, $NBYTES bytes   manifest.csv sha256 $MAN_SHA"
    echo
    echo "Per domain (OK / EMPTY / NOT FOUND / SKIPPED / FAILED+TIMEOUT+DENIED):"
    awk -F'\t' 'NR>1{d=$3; t[d]=1; if($8=="OK")o[d]++; else if($8=="EMPTY")e[d]++; else if($8=="NOT FOUND")n[d]++; else if($8=="SKIPPED")s[d]++; else f[d]++} END{for(d in t) printf "  %s  %4d %4d %4d %4d %4d\n", d, o[d], e[d], n[d], s[d], f[d]}' "$I" | sort
    echo
    echo "COLLECTED (status OK):"
    awk -F'\t' 'FILENAME==ARGV[1]{if(FNR>1) p[$1]=$11; next} FNR>1 && $8=="OK"{printf "  %-8s %s%s\n", $2, p[$2], ($16!="" && $16!="-") ? "  ["$16"]" : ""}' "$CAT" "$I"
    echo
    echo "NOT COLLECTED (with reason):"
    awk -F'\t' 'FILENAME==ARGV[1]{if(FNR>1) p[$1]=$11; next} FNR>1 && ($8=="NOT FOUND"||$8=="SKIPPED"||$8=="EMPTY"){printf "  %-8s %-10s %-22s %s\n", $2, $8, $9, p[$2]}' "$CAT" "$I"
    echo
    echo "FAILED / TIMEOUT / DENIED (with reason and first error line):"
    awk -F'\t' 'FNR>1 && ($8=="FAILED"||$8=="TIMEOUT"||$8=="DENIED"){printf "  %-8s %-8s %-18s %s\n", $2, $8, $9, $16}' "$I"
    echo
    echo "Sub-results that need attention (from multi-part items):"
    awk -F'\t' '$2!="OK"{printf "  %-8s %-10s %-22s %s\n", $1, $2, $3, $4}' "$W/subs.tsv" | head -n 500
    echo
    echo "Kit: $KIT  signature $KIT_SIG  SHA256SUMS sha256 $KIT_SUMS_SHA  public key $KIT_PUBKEY"
    awk -F, 'NR>1 && $2!="OK"{print "  kit file "$1": "$2" -> "$5}' "$C/kit-integrity.csv"
    [ -n "$OPT_FORCE" ] && echo "  --force-untrusted-kit used, reason: $OPT_FORCE"
    echo "Programs from the server used (UNTRUSTED_TOOL): $(awk -F, 'NR>1 && $2=="server"' "$C/tools-used.csv" | wc -l) (see tools-used.csv)"
    echo "Details: manifest.csv (every file), failures.csv, not-collected.csv, tools-used.csv, items.tsv, collector.log"
  } > "$C/report.txt"
  # 7. chain-of-custody.txt
  {
    banner_narrow 2>/dev/null
    echo "CHAIN OF CUSTODY - Corpus-0mnia Forensics (C0F) $C0F_VERSION"
    echo "KIT INTEGRITY: $KIT_INTEGRITY${KIT_CHANGED:+ (KIT CHANGED DURING RUN)}    COLLECTION STATUS: $RUN_STATUS"
    echo
    echo "Case number          : $CASE"
    echo "Examiner             : $EXAMINER"
    echo "Run as               : $C0F_EUSER (uid $C0F_EUID), invoked by $C0F_INVOKER"
    echo "Examiner notes       : start: ${NOTE_START:--} | end: ${NOTE_END:--}"
    echo
    echo "HOST"
    echo "  hostname (short/raw): $HOST / $HOST_RAW ${HOST_NOTE:+($HOST_NOTE)}"
    echo "  IP addresses        : $(ip -o addr show 2>/dev/null | awk '{print $2"="$4}' | tr '\n' ' ')"
    echo "  machine-id          : $(cat /etc/machine-id 2>/dev/null)"
    echo "  DMI product / serial: $(cat /sys/class/dmi/id/product_name 2>/dev/null) / $(cat /sys/class/dmi/id/product_serial 2>/dev/null)   UUID $(cat /sys/class/dmi/id/product_uuid 2>/dev/null)"
    echo "  OS                  : $OS_NAME, kernel $(uname -r), $ARCH; in container: $C0F_IN_CONTAINER"
    echo
    echo "TIME"
    echo "  start UTC / local   : $RUN_START_UTC / $RUN_START_LOCAL"
    echo "  end   UTC / local   : $RUN_END_UTC / $RUN_END_LOCAL"
    echo "  trusted clock start : ${TRUSTED_START:-not given} (server UTC at entry: ${TRUSTED_START_SERVER:--})"
    echo "  trusted clock end   : ${TRUSTED_END:-not given} (server UTC at entry: ${TRUSTED_END_SERVER:--})"
    echo "  time zone           : $(date +%Z%z) TZ=$(cat /etc/timezone 2>/dev/null || readlink /etc/localtime)"
    echo
    echo "TOOLKIT"
    echo "  kit folder          : $KIT"
    echo "  signature           : $KIT_SIG   public key: $KIT_PUBKEY"
    echo "  SHA256SUMS sha256   : $KIT_SUMS_SHA"
    echo "  c0f.sh sha256       : $(sha "$KIT/c0f.sh")"
    echo "  options             : $ORIG_ARGS"
    echo
    echo "OUTPUT"
    echo "  folder              : $OUTDIR (examined system disk: $( [ "$OUT_EXTERNAL" = YES ] && echo no || echo YES))"
    [ "$OUT_EXTERNAL" = YES ] || echo "  note                : output was written to the examined system (decision recorded; RFC 3227 / ACPO principle 1 deviation)"
    echo "  evidence files      : $NFILES files, $NBYTES bytes"
    echo "  manifest.csv sha256 : $MAN_SHA"
    echo "  manifest.csv md5    : $MAN_MD5"
    echo "  counts              : OK $N_OK, EMPTY $N_EMPTY, NOT FOUND $N_NF, SKIPPED $N_SKIP, FAILED $N_FAIL, TIMEOUT $N_TO, DENIED $N_DEN"
    echo "  archive             : hash of the archive is written OUTSIDE the archive (<name>.sha256 and the end of <name>.custody.txt)"
    echo
    echo "HANDOVER (fill in by hand)"
    echo "  Collected by: ______________________  Date/time: ____________  Signature: __________"
    echo "  Received by : ______________________  Date/time: ____________  Signature: __________"
    echo "  Storage location: ___________________________________________________________"
  } > "$C/chain-of-custody.txt"
  return 0
}
