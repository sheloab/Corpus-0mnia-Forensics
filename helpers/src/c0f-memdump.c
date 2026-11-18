/* SPDX-License-Identifier: MIT OR GPL-2.0-or-later
 * Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors */
/* c0f-memdump: dump the readable memory of ONE process through /proc/PID/mem (no ptrace attach, no kernel module).
 * Usage: c0f-memdump [-S] [-a] PID OUTPREFIX
 *   -S  stop the process (SIGSTOP) during the dump for a consistent image, then SIGCONT (only if it was running)
 *   -a  also try regions without the 'r' permission (normally recorded as SKIPPED)
 * Writes: OUTPREFIX.maps (copy of /proc/PID/maps), OUTPREFIX.mem (regions concatenated; zero pages kept sparse),
 *         OUTPREFIX.regions.tsv (where each region sits inside .mem, bytes read, unreadable pages),
 *         OUTPREFIX.info.txt (pid, comm, cmdline, uid, times, Yama ptrace_scope).
 * Exit: 0 ok, 1 partial (some regions unreadable), 2 usage/open error, 3 permission denied. */
#include "c0f_common.h"
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <sys/stat.h>
#define CH (1024*1024)
#define PG 4096

static pid_t target; static int stopped_by_us;
static void cont_and_exit(int s){ if(stopped_by_us) kill(target,SIGCONT); _exit(128+s); }
static char state_of(pid_t p){ char f[64],b[512]; snprintf(f,sizeof f,"/proc/%d/stat",(int)p); int fd=open(f,O_RDONLY); if(fd<0) return '?';
  ssize_t n=read(fd,b,sizeof b-1); close(fd); if(n<=0) return '?'; b[n]=0; char *r=strrchr(b,')'); return (r&&r[1]&&r[2])?r[2]:'?'; }
static int is_zero(const uint8_t *p, size_t n){ for(size_t i=0;i<n;i++) if(p[i]) return 0; return 1; }
static void copyfile(const char *src, const char *dst){ int i=open(src,O_RDONLY), o=open(dst,O_WRONLY|O_CREAT|O_EXCL,0600); char b[65536]; ssize_t n;
  if(i>=0&&o>=0) while((n=read(i,b,sizeof b))>0) if(write(o,b,n)!=n) break; if(i>=0)close(i); if(o>=0)close(o); }

int main(int argc, char **argv){
  int optS=0, optA=0, c;
  while((c=getopt(argc,argv,"SaV"))!=-1){ if(c=='S')optS=1; else if(c=='a')optA=1; else if(c=='V'){ printf("c0f-memdump %s (C0F helper)\n",C0F_HELPER_VERSION); return 0;} else return 2; }
  if (argc-optind!=2){ fprintf(stderr,"usage: c0f-memdump [-S] [-a] PID OUTPREFIX\n"); return 2; }
  target=(pid_t)atoi(argv[optind]); const char *pre=argv[optind+1];
  if (target<=0 || target==getpid()) { fprintf(stderr,"c0f-memdump: invalid pid\n"); return 2; }
  char p[PATH_MAX], q[PATH_MAX];
  snprintf(p,sizeof p,"/proc/%d/maps",(int)target); snprintf(q,sizeof q,"%s.maps",pre);
  FILE *maps=fopen(p,"r"); if(!maps){ fprintf(stderr,"c0f-memdump: %s: %s\n",p,strerror(errno)); return errno==EACCES||errno==EPERM?3:2; }
  copyfile(p,q);
  snprintf(p,sizeof p,"/proc/%d/mem",(int)target); int mfd=open(p,O_RDONLY|O_CLOEXEC);
  if (mfd<0){ int e=errno; fprintf(stderr,"c0f-memdump: %s: %s (Yama ptrace_scope / LSM may forbid it)\n",p,strerror(e)); return (e==EACCES||e==EPERM)?3:2; }
  snprintf(q,sizeof q,"%s.mem",pre); int ofd=open(q,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600); if(ofd<0){ perror(q); return 2; }
  snprintf(q,sizeof q,"%s.regions.tsv",pre); FILE *R=fopen(q,"wx"); if(!R){ perror(q); return 2; }
  signal(SIGINT,cont_and_exit); signal(SIGTERM,cont_and_exit); signal(SIGHUP,cont_and_exit);
  char st0=state_of(target);
  if (optS && st0!='T' && st0!='t' && st0!='Z') { if(kill(target,SIGSTOP)==0){ stopped_by_us=1; for(int i=0;i<200&&state_of(target)!='T';i++) usleep(10000);} }
  time_t t0=time(NULL);
  uint8_t *buf=malloc(CH); off_t dpos=0; char line[PATH_MAX+256]; long nreg=0, nbad=0; unsigned long long total=0, unread_pages=0;
  fprintf(R,"start\tend\tsize\tperms\tfile_offset\tdev\tinode\tpath\tdump_offset\tbytes_read\tunreadable_pages\tstatus\n");
  while (fgets(line,sizeof line,maps)) {
    unsigned long long s,e,off,ino; char perms[8]; unsigned dmaj,dmin; int n=0;
    if (sscanf(line,"%llx-%llx %7s %llx %x:%x %llu %n",&s,&e,perms,&off,&dmaj,&dmin,&ino,&n)<7) continue;
    char *path=line+n; path[strcspn(path,"\n")]=0; nreg++;
    const char *status="OK"; unsigned long long got=0, bad=0; off_t start=dpos;
    if (s>=0x8000000000000000ULL || !strcmp(path,"[vsyscall]")) status="SKIPPED_KERNEL_REGION";
    else if (!strncmp(path,"[vvar",5)) status="SKIPPED_VVAR";
    else if (perms[0]!='r' && !optA) status="SKIPPED_NOT_READABLE";
    else {
      for (unsigned long long a=s;a<e;) { size_t want=(size_t)((e-a)>CH?CH:(e-a)); ssize_t r=pread(mfd,buf,want,(off_t)a);
        if (r<=0) { /* fall back to page by page for this chunk */
          for (size_t k=0;k<want;k+=PG){ ssize_t r2=pread(mfd,buf+k,PG,(off_t)(a+k)); if(r2!=PG){ memset(buf+k,0,PG); bad++; } else got+=PG; }
          r=(ssize_t)want; }
        else got+=(unsigned long long)r;
        if (is_zero(buf,(size_t)r)) dpos+=r; else { if(lseek(ofd,dpos,SEEK_SET)<0||write(ofd,buf,(size_t)r)!=r){ status="WRITE_ERROR"; break;} dpos+=r; }
        a+=(unsigned long long)r; }
      if (!strcmp(status,"OK") && bad) status = got?"PARTIAL":"UNREADABLE";
      if (bad) nbad++; unread_pages+=bad; total+=got;
    }
    fprintf(R,"0x%llx\t0x%llx\t%llu\t%s\t0x%llx\t%x:%x\t%llu\t",s,e,e-s,perms,off,dmaj,dmin,ino); tsv_str(R,path);
    if (!strncmp(status,"SKIPPED",7)) fprintf(R,"\t-\t0\t-\t%s\n",status); else fprintf(R,"\t%lld\t%llu\t%llu\t%s\n",(long long)start,got,bad,status);
  }
  if (ftruncate(ofd,dpos)) {}
  time_t t1=time(NULL);
  if (stopped_by_us) kill(target,SIGCONT);
  fclose(maps); close(mfd); close(ofd); fclose(R);
  /* info file */
  snprintf(q,sizeof q,"%s.info.txt",pre); FILE *I=fopen(q,"wx");
  if (I) { char t[64], b[4096]; fmt_utc(t,sizeof t,t0,-1); fprintf(I,"pid: %d\ndump_start_utc: %s\n",(int)target,t); fmt_utc(t,sizeof t,t1,-1); fprintf(I,"dump_end_utc: %s\n",t);
    fprintf(I,"process_state_before: %c\nstopped_during_dump: %s\nregions: %ld\nregions_with_unreadable_pages: %ld\nbytes_read: %llu\nunreadable_pages: %llu\n",st0,stopped_by_us?"yes (SIGSTOP/SIGCONT)":"no",nreg,nbad,total,unread_pages);
    const char *fs[]={"comm","cmdline","loginuid","sessionid","cgroup"}; for(int i=0;i<5;i++){ snprintf(p,sizeof p,"/proc/%d/%s",(int)target,fs[i]); int fd=open(p,O_RDONLY); ssize_t n=fd>=0?read(fd,b,sizeof b-1):-1; if(fd>=0)close(fd);
      fprintf(I,"%s: ",fs[i]); if(n>0){ for(ssize_t k=0;k<n;k++) if(!b[k]) b[k]=' '; tsv_put(I,b,(size_t)n);} else fputs("-",I); fputc('\n',I); }
    snprintf(p,sizeof p,"/proc/%d/exe",(int)target); ssize_t n=readlink(p,b,sizeof b-1); if(n>0){b[n]=0; fprintf(I,"exe: "); tsv_str(I,b); fputc('\n',I);}
    int fd=open("/proc/sys/kernel/yama/ptrace_scope",O_RDONLY); n=fd>=0?read(fd,b,8):-1; if(fd>=0)close(fd); fprintf(I,"yama_ptrace_scope: %s",n>0?(b[n]=0,b):"absent\n");
    fprintf(I,"note: .mem holds the readable regions back to back; regions.tsv gives each region's dump_offset. Unreadable pages are zero-filled.\n");
    fclose(I); }
  fprintf(stderr,"c0f-memdump: pid %d regions=%ld bytes=%llu unreadable_pages=%llu\n",(int)target,nreg,total,unread_pages);
  return nbad?1:0;
}
