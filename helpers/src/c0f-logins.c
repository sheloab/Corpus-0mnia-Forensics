/* SPDX-License-Identifier: MIT OR GPL-2.0-or-later
 * Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors */
/* c0f-logins: parser for classic login records, independent of the server's own tools and of libc struct layouts.
 *   c0f-logins utmp    [-r RECSIZE] FILE            utmp / wtmp / btmp (glibc layout, 384-byte records)
 *   c0f-logins lastlog [-r RECSIZE] [-p PASSWD] FILE  /var/log/lastlog (292-byte records; 296 on 32-bit time64)
 *   c0f-logins faillog [-r RECSIZE] [-p PASSWD] FILE  /var/log/faillog  (32-byte records on 64-bit, 24 on 32-bit)
 * Output: TSV with a header. utmp rows carry an "anomaly" column (zeroed record = typical log-wiper trace,
 * time going backwards, unknown type, future time, non-printable text, trailing partial record).
 * Little-endian targets only (x86_64, aarch64, armv7). The file is opened with O_NOATIME when possible. */
#include "c0f_common.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#ifndef O_NOATIME
#define O_NOATIME 01000000
#endif
#ifndef SEEK_DATA
#define SEEK_DATA 3
#define SEEK_HOLE 4
#endif

static int32_t le32(const uint8_t *p){ return (int32_t)((uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24); }
static int16_t le16(const uint8_t *p){ return (int16_t)(p[0]|p[1]<<8); }
static int64_t le64(const uint8_t *p){ return (int64_t)((uint64_t)(uint32_t)le32(p)|((uint64_t)(uint32_t)le32(p+4))<<32); }

static int open_ro(const char *f){ int fd=open(f,O_RDONLY|O_CLOEXEC|O_NOATIME); if(fd<0&&errno==EPERM) fd=open(f,O_RDONLY|O_CLOEXEC); return fd; }
static int readfull(int fd, uint8_t *b, size_t n, off_t off){ size_t got=0; while(got<n){ ssize_t r=pread(fd,b+got,n-got,off+got); if(r<0){if(errno==EINTR)continue; return -1;} if(!r)break; got+=r;} return (int)got; }

/* ---- passwd map ---- */
typedef struct { long uid; char name[64]; } pw_t; static pw_t *pw; static size_t npw;
static void load_passwd(const char *f){ FILE *p=fopen(f,"r"); if(!p){ fprintf(stderr,"c0f-logins: cannot read %s: %s\n",f,strerror(errno)); return; }
  char line[1024]; while(fgets(line,sizeof line,p)){ char *c1=strchr(line,':'); if(!c1) continue; char *c2=strchr(c1+1,':'); if(!c2) continue; char *c3=strchr(c2+1,':'); if(!c3) continue;
    *c1=0; *c3=0; pw=realloc(pw,(npw+1)*sizeof *pw); pw[npw].uid=strtol(c2+1,NULL,10); snprintf(pw[npw].name,sizeof pw[npw].name,"%s",line); npw++; } fclose(p); }
static const char *uidname(long uid){ for(size_t i=0;i<npw;i++) if(pw[i].uid==uid) return pw[i].name; return NULL; }

static int nonprint(const uint8_t *s, size_t max){ for(size_t i=0;i<max&&s[i];i++) if(s[i]<0x20||s[i]==0x7f) return 1; return 0; }
static const char *utype(int t){ static const char *n[]={"EMPTY","RUN_LVL","BOOT_TIME","NEW_TIME","OLD_TIME","INIT_PROCESS","LOGIN_PROCESS","USER_PROCESS","DEAD_PROCESS","ACCOUNTING"}; return (t>=0&&t<=9)?n[t]:"UNKNOWN"; }

static int do_utmp(const char *f, int rs){
  int fd=open_ro(f); if(fd<0){ fprintf(stderr,"c0f-logins: %s: %s\n",f,strerror(errno)); return 1; }
  struct stat st; fstat(fd,&st); if(!rs) rs=384;
  printf("rec\toffset\ttype\ttype_name\tpid\tline\tid\tuser\thost\taddr\texit_term\texit_code\tsession\ttime_utc\tanomaly\n");
  uint8_t *r=malloc(rs); int64_t prev=0; long n=0; time_t now=time(NULL); long zero=0, back=0;
  for (off_t off=0;;off+=rs,n++) { int got=readfull(fd,r,rs,off); if(got<=0) break;
    if (got<rs) { printf("%ld\t%lld\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\tTRAILING_PARTIAL_RECORD(%d bytes)\n",n,(long long)off,got); break; }
    char an[256]=""; int allz=1; for(int i=0;i<rs;i++) if(r[i]){allz=0;break;}
    int type=le16(r); int32_t pid=le32(r+4), sess=le32(r+336), tsec=le32(r+340), tus=le32(r+344);
    if (allz) { strcat(an,"ALL_ZERO_RECORD;"); zero++; }
    else {
      if (type<0||type>9) strcat(an,"UNKNOWN_TYPE;");
      if (tsec==0 && type!=0) strcat(an,"TIME_ZERO;");
      if (tsec && prev && tsec<prev) { char b[64]; snprintf(b,sizeof b,"TIME_BACKWARDS(%llds);",(long long)(prev-tsec)); strcat(an,b); back++; }
      if (tsec > (int64_t)now+86400) strcat(an,"FUTURE_TIME;");
      if (nonprint(r+8,32)||nonprint(r+44,32)||nonprint(r+76,256)) strcat(an,"NONPRINTABLE_TEXT;");
      if (tus<0||tus>999999) strcat(an,"BAD_USEC;");
      if (tsec) prev=tsec;
    }
    char addr[64]="-"; const uint8_t *a=r+348;
    if (le32(a+4)==0&&le32(a+8)==0&&le32(a+12)==0) { if(le32(a)) snprintf(addr,sizeof addr,"%u.%u.%u.%u",a[0],a[1],a[2],a[3]); }
    else { int o=0; for(int i=0;i<16;i+=2) o+=snprintf(addr+o,sizeof addr-o,"%s%x",i?":":"",(a[i]<<8)|a[i+1]); }
    char t[64]; if(tsec){ fmt_utc(t,sizeof t,(int64_t)(uint32_t)tsec,-1); } else strcpy(t,"-");
    printf("%ld\t%lld\t%d\t%s\t%d\t",n,(long long)off,type,utype(type),pid); tsv_fixed(stdout,(char*)r+8,32); putchar('\t'); tsv_fixed(stdout,(char*)r+40,4); putchar('\t');
    tsv_fixed(stdout,(char*)r+44,32); putchar('\t'); tsv_fixed(stdout,(char*)r+76,256);
    printf("\t%s\t%d\t%d\t%d\t%s\t%s\n",addr,le16(r+332),le16(r+334),sess,t,*an?an:"-");
  }
  fprintf(stderr,"c0f-logins: %s records=%ld zeroed=%ld backwards=%ld size=%lld recsize=%d%s\n",f,n,zero,back,(long long)st.st_size,rs,(st.st_size%rs)?" (size not a multiple of recsize)":"");
  close(fd); free(r); return 0;
}

static void walk_sparse(int fd, off_t size, int rs, void (*cb)(long idx, const uint8_t *r, int rs)) {
  uint8_t *r=malloc(rs); off_t pos=0; long last=-1;
  while (pos<size) { off_t d=lseek(fd,pos,SEEK_DATA); if(d<0){ if(errno==ENXIO) break; d=pos; }
    off_t e=lseek(fd,d,SEEK_HOLE); if(e<0) e=size;
    long first=(long)(d/rs); for (off_t off=(off_t)first*rs; off<e && off+rs<=size; off+=rs) { long idx=(long)(off/rs); if(idx<=last) continue; if(readfull(fd,r,rs,off)!=rs) break; last=idx; cb(idx,r,rs); }
    pos = e>d?e:d+rs; }
  free(r);
}
static void ll_cb(long uid, const uint8_t *r, int rs){
  int64_t t = rs==296 ? le64(r) : (int64_t)(uint32_t)le32(r); int toff = rs==296?8:4;
  if (!t && !r[toff] && !r[toff+32]) return;
  char ts[64]; if(t) fmt_utc(ts,sizeof ts,t,-1); else strcpy(ts,"-"); const char *nm=uidname(uid);
  printf("%ld\t%s\t%s\t",uid,nm?nm:(npw?"(uid not in passwd)":"-"),ts); tsv_fixed(stdout,(const char*)r+toff,32); putchar('\t'); tsv_fixed(stdout,(const char*)r+toff+32,256);
  printf("\t%s\n", (t>(int64_t)time(NULL)+86400)?"FUTURE_TIME":"-");
}
static void fl_cb(long uid, const uint8_t *r, int rs){
  int cnt=le16(r), mx=le16(r+2); int64_t t = rs==24 ? (int64_t)le32(r+16) : le64(r+16); int64_t lk = rs==24 ? (int64_t)le32(r+20) : le64(r+24);
  if (!cnt && !t) return; char ts[64]; if(t) fmt_utc(ts,sizeof ts,t,-1); else strcpy(ts,"-"); const char *nm=uidname(uid);
  printf("%ld\t%s\t%d\t%d\t%s\t",uid,nm?nm:(npw?"(uid not in passwd)":"-"),cnt,mx,ts); tsv_fixed(stdout,(const char*)r+4,12); printf("\t%lld\n",(long long)lk);
}
static int do_sparse(const char *f, int rs, int is_ll){
  int fd=open_ro(f); if(fd<0){ fprintf(stderr,"c0f-logins: %s: %s\n",f,strerror(errno)); return 1; }
  struct stat st; fstat(fd,&st);
  if (!rs) { if (is_ll) rs = (st.st_size%292==0)?292:((st.st_size%296==0)?296:292);
             else rs = sizeof(long)==8 ? 32 : ((st.st_size%24==0)?24:32); }
  if (is_ll) { printf("uid\tuser\tlast_login_utc\tline\thost\tanomaly\n"); walk_sparse(fd,st.st_size,rs,ll_cb); }
  else { printf("uid\tuser\tfail_count\tfail_max\tlast_fail_utc\tline\tlock_time\n"); walk_sparse(fd,st.st_size,rs,fl_cb); }
  fprintf(stderr,"c0f-logins: %s size=%lld allocated=%lld recsize=%d%s\n",f,(long long)st.st_size,(long long)st.st_blocks*512,rs,(st.st_size%rs)?" (size not a multiple of recsize: check -r)":"");
  close(fd); return 0;
}

int main(int argc, char **argv){
  if (argc>1 && !strcmp(argv[1],"-V")) { printf("c0f-logins %s (C0F helper)\n",C0F_HELPER_VERSION); return 0; }
  if (argc<3) { fprintf(stderr,"usage: c0f-logins utmp|lastlog|faillog [-r RECSIZE] [-p PASSWD] FILE\n"); return 2; }
  const char *mode=argv[1]; int rs=0, c; optind=2;
  while ((c=getopt(argc,argv,"r:p:"))!=-1) { if(c=='r') rs=atoi(optarg); else if(c=='p') load_passwd(optarg); else return 2; }
  if (optind>=argc) { fprintf(stderr,"c0f-logins: FILE missing\n"); return 2; }
  if (!strcmp(mode,"utmp")) return do_utmp(argv[optind],rs);
  if (!strcmp(mode,"lastlog")) return do_sparse(argv[optind],rs,1);
  if (!strcmp(mode,"faillog")) return do_sparse(argv[optind],rs,0);
  fprintf(stderr,"c0f-logins: unknown mode %s\n",mode); return 2;
}
