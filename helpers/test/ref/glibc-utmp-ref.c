/* SPDX-License-Identifier: MIT OR GPL-2.0-or-later
 * Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors */
/* Reference reader using glibc's own struct utmp / struct lastlog (x86_64), for cross-checking c0f-logins. */
#include <stdio.h>
#include <utmp.h>
#include <lastlog.h>
#include <time.h>
#include <string.h>
int main(int c, char **v){
  FILE *f=fopen(v[2],"rb"); if(!f) return 1;
  if(!strcmp(v[1],"utmp")){ struct utmp u; long n=0; printf("sizeof=%zu\n",sizeof u);
    while(fread(&u,sizeof u,1,f)==1){ char t[32]; time_t s=u.ut_tv.tv_sec; strftime(t,sizeof t,"%Y-%m-%dT%H:%M:%S",gmtime(&s));
      printf("%ld\t%d\t%d\t%.32s\t%.32s\t%.256s\t%s\n",n++,u.ut_type,u.ut_pid,u.ut_line,u.ut_user,u.ut_host,s?t:"-"); } }
  else { struct lastlog l; long uid=0; printf("sizeof=%zu\n",sizeof l);
    while(fread(&l,sizeof l,1,f)==1){ if(l.ll_time){ char t[32]; time_t s=l.ll_time; strftime(t,sizeof t,"%Y-%m-%dT%H:%M:%S",gmtime(&s)); printf("%ld\t%s\t%.32s\t%.256s\n",uid,t,l.ll_line,l.ll_host);} uid++; } }
  return 0; }
