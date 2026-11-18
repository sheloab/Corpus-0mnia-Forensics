#!/bin/bash
# Types answers into a recorded C0F run only after each prompt is visible.  usage: feed-all.sh LOG demo|abort|ctrlc|none
F=$1; M=$2
w(){ until tr -d '\r' < "$F" 2>/dev/null | grep -qF -- "$1"; do sleep 0.5; done; sleep 1.2; }
[ "$M" = none ] && { w "[exit code:"; exit 0; }
w "Save output to";            printf '\r'
w "Case / ticket number";      printf 'IR-2026-0042\r'
w "Examiner name";             printf 'J. Analyst\r'
w "TRUSTED clock (phone/GPS)"; printf '%s\r' "$(date -u '+%Y-%m-%d %H:%M:%S')"
w "Examiner note";             printf 'web shell alert from WAF on demo-server\r'
if [ "$M" = abort ]; then w "Type YES"; printf 'no\r'; w "[exit code:"; exit 0; fi
w "Type YES";                  printf 'YES\r'
if [ "$M" = ctrlc ]; then w "(120/227)"; sleep 2; printf '\003'; fi
w "TRUSTED clock again";       printf '%s\r' "$(date -u '+%Y-%m-%d %H:%M:%S')"
if [ "$M" = ctrlc ]; then w "closing note"; printf 'stopped by operator\r'
else w "closing note"; printf 'collection done, archive handed to SOC\r'; fi
w "[exit code:"
