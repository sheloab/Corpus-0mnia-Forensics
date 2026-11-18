/* SPDX-License-Identifier: MIT OR GPL-2.0-or-later
 * Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors */
/* c0f-copy: evidence-preserving file copier for C0F (Corpus-0mnia Forensics).
 * - opens sources with O_NOATIME (falls back without it and records that), never follows symlinks
 *   (except top-level arguments with -F), records full metadata (statx incl. birth time) BEFORE reading,
 * - hashes the bytes actually read (SHA-256), detects files that change while being copied,
 * - copies sparse files by extent, splits output on EFBIG (FAT32 4 GiB limit), encodes names the
 *   destination filesystem rejects, writes one TSV metadata row per object.
 * Usage: c0f-copy [-R] [-x] [-F] [-n] [-H] [-t SEC] [-s MAXBYTES] [-e EXCLUDE]... [-M META.tsv] [-L LIST] -o DESTROOT [SRC...]
 *   -n  metadata only (no copy)    -D  digest only: read every file, SHA-256 + MD5 (note column md5=...), no copy
 *   -B FILE  also write a bodyfile (TSK/mactime 3.x format) with epoch times, e.g. for a filesystem timeline
 */
#include "c0f_common.h"
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>

#ifndef O_NOATIME
#define O_NOATIME 01000000
#endif
#ifndef SEEK_DATA
#define SEEK_DATA 3
#define SEEK_HOLE 4
#endif
#define BUFSZ (1024*1024)
#define SPARSE_HASH_LIMIT (256ULL*1024*1024)
#define PART_SUFFIX ".c0f-part"

struct kstatx_ts { int64_t tv_sec; uint32_t tv_nsec; int32_t pad; };
struct kstatx { uint32_t mask, blksize; uint64_t attributes; uint32_t nlink, uid, gid; uint16_t mode, spare0;
  uint64_t ino, size, blocks, attributes_mask; struct kstatx_ts atime, btime, ctime, mtime;
  uint32_t rdev_major, rdev_minor, dev_major, dev_minor; uint64_t spare[14]; };

typedef struct { uint32_t mode, uid, gid; uint64_t size, ino, nlink, blocks; uint32_t dmaj, dmin, rmaj, rmin;
  int64_t as, ms, cs, bs; long an, mn, cn, bn; int have_b; } meta_t;

static int opt_R, opt_x, opt_F, opt_n, opt_H, opt_t, opt_D; static unsigned long long opt_s; static FILE *BF;
static char **excl; static int nexcl; static FILE *M; static char destroot[PATH_MAX];
static char *buf; static volatile sig_atomic_t timed_out;
static unsigned long cnt_ok, cnt_fail;

static void on_alarm(int s){ (void)s; timed_out=1; }

static int get_meta(int dfd, const char *path, int flags, meta_t *m) {
  struct kstatx x; memset(&x,0,sizeof x);
#ifdef SYS_statx
  if (syscall(SYS_statx, dfd, path, flags, 0xfff /*STATX_BASIC_STATS|STATX_BTIME*/, &x) == 0) {
    m->mode=x.mode; m->uid=x.uid; m->gid=x.gid; m->size=x.size; m->ino=x.ino; m->nlink=x.nlink; m->blocks=x.blocks;
    m->dmaj=x.dev_major; m->dmin=x.dev_minor; m->rmaj=x.rdev_major; m->rmin=x.rdev_minor;
    m->as=x.atime.tv_sec; m->an=x.atime.tv_nsec; m->ms=x.mtime.tv_sec; m->mn=x.mtime.tv_nsec; m->cs=x.ctime.tv_sec; m->cn=x.ctime.tv_nsec;
    m->have_b = (x.mask & 0x800) ? 1 : 0; m->bs=x.btime.tv_sec; m->bn=x.btime.tv_nsec; return 0;
  }
  if (errno != ENOSYS && errno != EINVAL && errno != EPERM) return -1; /* EPERM: old container seccomp */
#endif
  struct stat st; int r = (flags & 0x1000 /*AT_EMPTY_PATH*/) ? fstat(dfd,&st) : fstatat(dfd,path,&st,flags);
  if (r) return -1;
  m->mode=st.st_mode; m->uid=st.st_uid; m->gid=st.st_gid; m->size=st.st_size; m->ino=st.st_ino; m->nlink=st.st_nlink; m->blocks=st.st_blocks;
  m->dmaj=major(st.st_dev); m->dmin=minor(st.st_dev); m->rmaj=major(st.st_rdev); m->rmin=minor(st.st_rdev);
  m->as=st.st_atim.tv_sec; m->an=st.st_atim.tv_nsec; m->ms=st.st_mtim.tv_sec; m->mn=st.st_mtim.tv_nsec; m->cs=st.st_ctim.tv_sec; m->cn=st.st_ctim.tv_nsec; m->have_b=0;
  return 0;
}
static char typech(uint32_t mode){ switch(mode&S_IFMT){case S_IFREG:return 'f';case S_IFDIR:return 'd';case S_IFLNK:return 'l';case S_IFCHR:return 'c';case S_IFBLK:return 'b';case S_IFIFO:return 'p';case S_IFSOCK:return 's';} return '?'; }
static const char *errstatus(int e){ switch(e){case ENOENT:case ENOTDIR:return "NOT_FOUND";case EACCES:case EPERM:return "PERMISSION_DENIED";case EINTR:return "TIMEOUT";case ENOSPC:case EDQUOT:return "NO_SPACE";} return "FAILED"; }

static void modestr(uint32_t m, char *o){ o[0]=typech(m)=='f'?'-':typech(m); const char *r="rwxrwxrwx"; for(int i=0;i<9;i++) o[1+i]=(m&(0400>>i))?r[i]:'-';
  if(m&04000) o[3]=(m&0100)?'s':'S'; if(m&02000) o[6]=(m&010)?'s':'S'; if(m&01000) o[9]=(m&01)?'t':'T'; o[10]=0; }
static void body(const char *src, const meta_t *m, const char *lnk, const char *md5){
  if (!BF || !m) return; char ms[12]; modestr(m->mode,ms);
  fprintf(BF,"%s|",md5&&*md5?md5:"0"); for(const char *c=src;*c;c++) fputc((*c=='|'||*c=='\n')?'?':*c,BF);
  if (lnk) { fputs(" -> ",BF); for(const char *c=lnk;*c;c++) fputc((*c=='|'||*c=='\n')?'?':*c,BF); }
  fprintf(BF,"|%llu|%s|%u|%u|%llu|%lld|%lld|%lld|%lld\n",(unsigned long long)m->ino,ms,m->uid,m->gid,(unsigned long long)m->size,(long long)m->as,(long long)m->ms,(long long)m->cs,m->have_b?(long long)m->bs:0LL);
}
static void row(const char *status, const char *src, const char *dst, const meta_t *m, const char *lnk, const char *noat,
                long long nread, const char *hash, const char *note) {
  char t[64]; body(src,m,lnk,NULL);
  if (!strcmp(status,"OK")||!strcmp(status,"EMPTY")||!strcmp(status,"CHANGED_DURING_COPY")) cnt_ok++; else if (strncmp(status,"SKIPPED",7)) cnt_fail++;
  fprintf(M,"%s\t",status); tsv_str(M,src); fputc('\t',M);
  if (dst && *dst) { const char *r = dst, *base=getenv("C0F_OUT"); size_t bl = base ? strlen(base) : 0, dl=strlen(destroot);
    if (bl && !strncmp(dst,base,bl) && dst[bl]=='/') r=dst+bl; else if(!strncmp(dst,destroot,dl)) r=dst+dl; tsv_str(M,r);} else fputc('-',M);
  if (m) {
    fprintf(M,"\t%c\t%llu\t%04o\t%u\t%u\t%llu\t%llu\t%u:%u\t", typech(m->mode),(unsigned long long)m->size,m->mode&07777,m->uid,m->gid,(unsigned long long)m->ino,(unsigned long long)m->nlink,m->dmaj,m->dmin);
    fmt_utc(t,sizeof t,m->as,m->an); fprintf(M,"%s\t",t); fmt_utc(t,sizeof t,m->ms,m->mn); fprintf(M,"%s\t",t);
    fmt_utc(t,sizeof t,m->cs,m->cn); fprintf(M,"%s\t",t);
    if (m->have_b) { fmt_utc(t,sizeof t,m->bs,m->bn); fprintf(M,"%s\t",t);} else fputs("-\t",M);
  } else fputs("\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t",M);
  if (lnk) tsv_str(M,lnk); else fputc('-',M);
  fprintf(M,"\t%s\t",noat?noat:"-"); if(nread>=0) fprintf(M,"%lld",nread); else fputc('-',M);
  fprintf(M,"\t%s\t",hash&&*hash?hash:"-"); if(note&&*note) tsv_str(M,note); else fputc('-',M); fputc('\n',M);
}

static int excluded(const char *p){ for(int i=0;i<nexcl;i++){ size_t l=strlen(excl[i]); if(!strncmp(p,excl[i],l)&&(p[l]==0||p[l]=='/'||(l==1&&excl[i][0]=='/'))) return 1; } return 0; }

/* encode characters that FAT/exFAT/NTFS reject, plus '%' so the mapping stays unambiguous */
static void enc_name(const char *in, char *out, size_t max){ size_t o=0; for(const unsigned char *p=(const unsigned char*)in;*p&&o+4<max;p++){
  if(*p<0x20||strchr("\"*:<>?\\|%",*p)) o+=snprintf(out+o,max-o,"%%%02X",*p); else out[o++]=*p; } out[o]=0; }

/* mkdir -p of DESTROOT/<dir>, encoding components the FS rejects; writes the real path to out */
static int mkdirs(const char *rel, char *out, size_t max) {
  snprintf(out,max,"%s",destroot); char comp[NAME_MAX*3+1], encd[NAME_MAX*3+1]; const char *p=rel;
  while (*p) { while(*p=='/') p++; if(!*p) break; size_t l=strcspn(p,"/"); if(l>NAME_MAX) { errno=ENAMETOOLONG; return -1; }
    memcpy(comp,p,l); comp[l]=0; p+=l; size_t ol=strlen(out);
    if (ol+l+2>=max) { errno=ENAMETOOLONG; return -1; }
    snprintf(out+ol,max-ol,"/%s",comp);
    if (mkdir(out,0700) && errno!=EEXIST) { if (errno==EINVAL||errno==EILSEQ) { out[ol]=0; enc_name(comp,encd,sizeof encd);
        if (ol+strlen(encd)+2>=max){errno=ENAMETOOLONG;return -1;} snprintf(out+ol,max-ol,"/%s",encd); if(mkdir(out,0700)&&errno!=EEXIST) return -1; } else return -1; }
  }
  return 0;
}

/* writer that splits on EFBIG */
typedef struct { char base[PATH_MAX]; int fd, part; } wr_t;
static int open_excl(char *path, size_t max) { /* creates path; on EEXIST appends .c0f-dupN; on EINVAL encodes name */
  for (int i=1;i<1000;i++) { int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600); if(fd>=0) return fd;
    if (errno==EEXIST) { char *d=strstr(path,".c0f-dup"); if(d) *d=0; size_t l=strlen(path); snprintf(path+l,max-l,".c0f-dup%d",i+1); continue; }
    if ((errno==EINVAL||errno==EILSEQ) && i==1) { char *sl=strrchr(path,'/'); char enc[NAME_MAX*3+1], nm[NAME_MAX*3+1]; snprintf(nm,sizeof nm,"%s",sl+1); enc_name(nm,enc,sizeof enc);
      if ((size_t)(sl-path)+strlen(enc)+2>=max){errno=ENAMETOOLONG;return -1;} snprintf(sl+1,max-(sl+1-path),"%s",enc); continue; }
    return -1; }
  errno=EEXIST; return -1;
}
static int wr_write(wr_t *w, const char *p, size_t n, char *note, size_t nmax) {
  while (n) { ssize_t r=write(w->fd,p,n);
    if (r<0) { if (errno==EINTR) continue;
      if (errno==EFBIG) { close(w->fd); w->part++; char pp[PATH_MAX]; snprintf(pp,sizeof pp,"%s%03d",w->base,w->part);
        w->fd=open(pp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600); if(w->fd<0) return -1;
        size_t l=strlen(note); snprintf(note+l,nmax-l,"%ssplit:%s%03d",l?"; ":"",PART_SUFFIX,w->part); continue; }
      return -1; }
    p+=r; n-=(size_t)r; }
  return 0;
}

/* -D: hash without copying. Sparse files with more than 256 MiB of holes are hashed per extent ("sparse:" prefix). */
static void digest_file(const char *src, const meta_t *pre, const char *lnk, int follow) {
  char noat[4]="yes", hash[80]="", note[160]=""; long long nread=0; int fl=O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NONBLOCK|(follow?0:O_NOFOLLOW);
  int fd=open(src,fl|O_NOATIME); if(fd<0&&errno==EPERM){ strcpy(noat,"no"); fd=open(src,fl); }
  if (fd<0) { int e=errno; row(errstatus(e),src,NULL,pre,lnk,"-",-1,NULL,strerror(e)); return; }
  meta_t m0; if (get_meta(fd,"",0x1000,&m0)) m0=*pre;
  if (!S_ISREG(m0.mode)) { close(fd); row("SKIPPED_SPECIAL",src,NULL,&m0,lnk,"-",-1,NULL,"not a regular file"); return; }
  sha256_ctx h; md5_ctx m5; sha256_init(&h); md5_init(&m5); int sparse_hash=0, rc=0;
  unsigned long long holes = m0.size > m0.blocks*512ULL ? m0.size - m0.blocks*512ULL : 0;
  if (m0.size > (1<<20) && holes > SPARSE_HASH_LIMIT) {
    off_t pos=0; sparse_hash=1;
    while ((unsigned long long)pos < m0.size) { off_t d=lseek(fd,pos,SEEK_DATA); if(d<0) break; off_t e=lseek(fd,d,SEEK_HOLE); if(e<0) e=(off_t)m0.size;
      for (off_t o=d;o<e;) { ssize_t r=pread(fd,buf,(size_t)((e-o)>BUFSZ?BUFSZ:(e-o)),o); if(r<=0){ if(r<0) rc=-1; break; }
        sha256_update(&h,&o,sizeof o); sha256_update(&h,buf,(size_t)r); md5_update(&m5,&o,sizeof o); md5_update(&m5,buf,(size_t)r); nread+=r; o+=r; }
      pos=e; }
  } else {
    for (;;) { ssize_t r=read(fd,buf,BUFSZ); if(r<0){ if(errno==EINTR) continue; rc=-1; break; } if(!r) break; sha256_update(&h,buf,(size_t)r); md5_update(&m5,buf,(size_t)r); nread+=r; }
  }
  close(fd);
  uint8_t d[32], d5[16]; char hx[65], h5[33]; sha256_final(&h,d); md5_final(&m5,d5); hex_encode(d,32,hx); hex_encode(d5,16,h5);
  snprintf(hash,sizeof hash,"%s%s",sparse_hash?"sparse:":"",hx); snprintf(note,sizeof note,"md5=%s%s%s",sparse_hash?"sparse:":"",h5,sparse_hash?"; sparse file hashed per extent":"");
  row(rc?"FAILED":(nread?"OK":"EMPTY"),src,NULL,&m0,lnk,noat,nread,hash,note);
}
static void copy_file(const char *src, const char *dstdir_real, const char *name, const meta_t *pre, int follow, const char *lnk) {
  char dst[PATH_MAX], note[1024]="", hash[80]="", noat[4]="yes"; long long nread=0; int fd=-1, saved=0;
  if (opt_D) { digest_file(src,pre,lnk,follow); return; }
  if (opt_n) { row("OK",src,NULL,pre,lnk,"-",-1,NULL,follow?"followed symlink":NULL); return; }
  if (opt_s && pre->size>opt_s) { row("SKIPPED_SIZE",src,NULL,pre,lnk,"-",-1,NULL,NULL); return; }
  int fl=O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NONBLOCK|(follow?0:O_NOFOLLOW);
  fd=open(src,fl|O_NOATIME); if (fd<0 && errno==EPERM) { strcpy(noat,"no"); fd=open(src,fl); }
  if (fd<0) { saved=errno; row(errstatus(saved),src,NULL,pre,lnk,"-",-1,NULL,strerror(saved)); return; }
  int f2=fcntl(fd,F_GETFL); if(f2>=0) fcntl(fd,F_SETFL,f2&~O_NONBLOCK);
  meta_t m0; if (get_meta(fd,"",0x1000,&m0)) m0=*pre;  /* metadata of what we actually opened */
  if (!S_ISREG(m0.mode)) { close(fd); row("SKIPPED_SPECIAL",src,NULL,&m0,lnk,"-",-1,NULL,"not a regular file at open time"); return; }
  snprintf(dst,sizeof dst,"%s/%s",dstdir_real,name);
  wr_t w; w.part=1; int ofd=open_excl(dst,sizeof dst); if(ofd<0){ saved=errno; close(fd); row(errstatus(saved),src,NULL,&m0,lnk,noat,-1,NULL,"cannot create destination"); return; }
  w.fd=ofd; snprintf(w.base,sizeof w.base,"%s%s",dst,PART_SUFFIX);
  sha256_ctx h; sha256_init(&h); timed_out=0; if(opt_t) alarm((unsigned)opt_t);
  int sparse = m0.size > (1<<20) && m0.blocks*512ULL < m0.size/2, rc=0, hashmode=0; /* hashmode 1 = sparse-hash */
  if (sparse) {
    unsigned long long holes=0; off_t pos=0; int ok=1; FILE *map=NULL; int packed=0;
    int exact = (m0.size - m0.blocks*512ULL) <= SPARSE_HASH_LIMIT; /* feed zeros for holes -> same value as sha256sum */
    static const uint8_t zero[65536];
    while ((unsigned long long)pos < m0.size) {
      off_t d=lseek(fd,pos,SEEK_DATA); if (d<0) { if(errno==ENXIO){ holes+=m0.size-pos; if(exact) for(off_t z=pos;(unsigned long long)z<m0.size;){ size_t k=(size_t)(((off_t)m0.size-z)>(off_t)sizeof zero?(off_t)sizeof zero:((off_t)m0.size-z)); sha256_update(&h,zero,k); z+=k; } break;} ok=0; break; }
      off_t e=lseek(fd,d,SEEK_HOLE); if (e<0) { ok=0; break; }
      holes+=(unsigned long long)(d-pos);
      if (exact) for (off_t z=pos; z<d;) { size_t k=(size_t)((d-z)>(off_t)sizeof zero?(off_t)sizeof zero:(d-z)); sha256_update(&h,zero,k); z+=k; }
      if (!packed && lseek(w.fd,d,SEEK_SET)<0) { ok=0; break; }
      for (off_t o=d;o<e;) { size_t want=(size_t)((e-o)>BUFSZ?BUFSZ:(e-o)); ssize_t r=pread(fd,buf,want,o);
        if (r<0){ if(errno==EINTR&&!timed_out) continue; rc=-1; saved=errno; break; } if(r==0) break;
        if (!packed) { ssize_t wv=pwrite(w.fd,buf,(size_t)r,o); if (wv!=r) { if (errno==EFBIG||errno==EINVAL) { /* switch to packed */
              packed=1; ftruncate(w.fd,0); lseek(w.fd,0,SEEK_SET); char mp[PATH_MAX]; snprintf(mp,sizeof mp,"%s.c0f-extents.tsv",dst); map=fopen(mp,"wx");
              size_t l=strlen(note); snprintf(note+l,sizeof note-l,"%spacked extents (see .c0f-extents.tsv)",l?"; ":"");
              lseek(fd,0,SEEK_SET); pos=0; holes=0; sha256_init(&h); nread=0; goto restart; } rc=-1; saved=errno; break; } }
        else { if (wr_write(&w,buf,(size_t)r,note,sizeof note)) { rc=-1; saved=errno; break; } if(map) fprintf(map,"%lld\t%lld\n",(long long)o,(long long)r); }
        if (!exact) sha256_update(&h,&o,sizeof o); sha256_update(&h,buf,(size_t)r); nread+=r; o+=r; }
      if (rc) break;
      pos=e; continue;
      restart: ;
    }
    if (map) fclose(map);
    if (!ok && !rc) { sparse=0; lseek(fd,0,SEEK_SET); lseek(w.fd,0,SEEK_SET); ftruncate(w.fd,0); sha256_init(&h); nread=0; }
    else { if (!packed && !rc && ftruncate(w.fd,(off_t)m0.size)) { /* keep data, record */ size_t l=strlen(note); snprintf(note+l,sizeof note-l,"%scannot set sparse length",l?"; ":""); }
      hashmode=exact?2:1; size_t l=strlen(note); snprintf(note+l,sizeof note-l,exact?"%ssparse: %llu hole bytes (hash = normal sha256)":"%ssparse: %llu hole bytes; hash=sha256 over (8-byte LE offset,data) per extent",l?"; ":"",holes); }
  }
  if (!sparse) {
    for (;;) { ssize_t r=read(fd,buf,BUFSZ); if (r<0) { if(errno==EINTR&&!timed_out) continue; rc=-1; saved=errno; break; } if(!r) break;
      if (wr_write(&w,buf,(size_t)r,note,sizeof note)) { rc=-1; saved=errno; break; }
      sha256_update(&h,buf,(size_t)r); nread+=r; }
  }
  alarm(0);
  meta_t m1; int changed = get_meta(fd,"",0x1000,&m1)==0 && (m1.size!=m0.size||m1.ms!=m0.ms||m1.mn!=m0.mn||m1.cs!=m0.cs||m1.cn!=m0.cn);
  struct timespec ts[2]={{(time_t)m0.as,m0.an},{(time_t)m0.ms,m0.mn}}; futimens(w.fd,ts);
  close(w.fd); close(fd);
  if (!opt_H || hashmode) { uint8_t d[32]; sha256_final(&h,d); hex_encode(d,32,hash); if(hashmode==1){ char t[80]; snprintf(t,sizeof t,"sparse:%s",hash); strcpy(hash,t);} }
  if (opt_H && !hashmode) hash[0]=0;
  if (rc) { size_t l=strlen(note); snprintf(note+l,sizeof note-l,"%sread/write error after %lld bytes: %s",l?"; ":"",nread,timed_out?"timeout":strerror(saved));
    row(timed_out?"TIMEOUT":errstatus(saved),src,dst,&m0,lnk,noat,nread,hash,note); return; }
  if (!sparse && (unsigned long long)nread != m0.size && m0.size) { size_t l=strlen(note); snprintf(note+l,sizeof note-l,"%sread %lld bytes, stat size %llu (pseudo or changing file)",l?"; ":"",nread,(unsigned long long)m0.size); }
  if (follow) { size_t l=strlen(note); snprintf(note+l,sizeof note-l,"%sfollowed symlink",l?"; ":""); }
  row(changed?"CHANGED_DURING_COPY":(nread==0?"EMPTY":"OK"),src,dst,&m0,lnk,noat,nread,hash,note);
}

static int namecmp(const void *a, const void *b){ return strcmp(*(char*const*)a,*(char*const*)b); }

static void walk(const char *src, const char *dstdir_real, const char *name, uint32_t topdev_maj, uint32_t topdev_min, int top) {
  meta_t m; char lnk[PATH_MAX]; const char *lp=NULL;
  if (excluded(src)) { row("SKIPPED_EXCLUDED",src,NULL,NULL,NULL,"-",-1,NULL,NULL); return; }
  if (get_meta(AT_FDCWD,src,AT_SYMLINK_NOFOLLOW,&m)) { int e=errno; row(errstatus(e),src,NULL,NULL,NULL,"-",-1,NULL,strerror(e)); return; }
  if (S_ISLNK(m.mode)) { ssize_t l=readlink(src,lnk,sizeof lnk-1); if(l>=0){lnk[l]=0; lp=lnk;}
    if (top && opt_F) { meta_t t; if (get_meta(AT_FDCWD,src,0,&t)==0 && S_ISREG(t.mode)) { row("OK",src,NULL,&m,lp,"-",-1,NULL,"symlink (content copied below)"); copy_file(src,dstdir_real,name,&t,1,lp); return; } }
    row("OK",src,NULL,&m,lp,"-",-1,NULL,"symlink recorded, not followed"); return; }
  if (opt_x && !top && (m.dmaj!=topdev_maj||m.dmin!=topdev_min)) { row("SKIPPED_OTHER_FS",src,NULL,&m,NULL,"-",-1,NULL,NULL); return; }
  if (S_ISREG(m.mode)) { copy_file(src,dstdir_real,name,&m,0,NULL); return; }
  if (!S_ISDIR(m.mode)) { row("SKIPPED_SPECIAL",src,NULL,&m,NULL,"-",-1,NULL,"device/fifo/socket: metadata only"); return; }
  /* directory */
  char ddir[PATH_MAX]="";
  if (!opt_n) { snprintf(ddir,sizeof ddir,"%s/%s",dstdir_real,name);
    if (mkdir(ddir,0700) && errno!=EEXIST) { if (errno==EINVAL||errno==EILSEQ) { char e[NAME_MAX*3+1]; enc_name(name,e,sizeof e); snprintf(ddir,sizeof ddir,"%s/%s",dstdir_real,e); mkdir(ddir,0700);} } }
  if (!top && !opt_R) { row("OK",src,ddir,&m,NULL,"-",-1,NULL,"directory (not descended)"); return; }
  int dfd=open(src,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC|O_NOATIME); const char *noat="yes";
  if (dfd<0 && errno==EPERM) { noat="no"; dfd=open(src,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); }
  if (dfd<0) { int e=errno; row(errstatus(e),src,ddir,&m,NULL,"-",-1,NULL,strerror(e)); return; }
  DIR *d=fdopendir(dfd); if(!d){ int e=errno; close(dfd); row("FAILED",src,ddir,&m,NULL,noat,-1,NULL,strerror(e)); return; }
  char **names=NULL; size_t n=0,cap=0; struct dirent *de;
  while ((de=readdir(d))) { if(!strcmp(de->d_name,".")||!strcmp(de->d_name,"..")) continue;
    if (n==cap){ cap=cap?cap*2:64; char **nn=realloc(names,cap*sizeof *names); if(!nn) break; names=nn; } names[n++]=strdup(de->d_name); }
  closedir(d);
  qsort(names,n,sizeof *names,namecmp);
  row("OK",src,ddir,&m,NULL,noat,-1,NULL,"directory");
  if (top || opt_R) for (size_t i=0;i<n;i++) { char child[PATH_MAX];
    if ((size_t)snprintf(child,sizeof child,"%s/%s",strcmp(src,"/")?src:"",names[i])>=sizeof child) { row("FAILED",names[i],NULL,NULL,NULL,"-",-1,NULL,"path too long"); free(names[i]); continue; }
    walk(child, opt_n?"":ddir, names[i], top?m.dmaj:topdev_maj, top?m.dmin:topdev_min, 0); free(names[i]); }
  free(names);
  if (!opt_n && *ddir) { struct timespec ts[2]={{(time_t)m.as,m.an},{(time_t)m.ms,m.mn}}; utimensat(AT_FDCWD,ddir,ts,AT_SYMLINK_NOFOLLOW); }
}

static void do_top(const char *arg) {
  char abs[PATH_MAX], parent[PATH_MAX], real[PATH_MAX];
  if (arg[0]=='/') snprintf(abs,sizeof abs,"%s",arg); else { char cwd[PATH_MAX]; if(!getcwd(cwd,sizeof cwd)) strcpy(cwd,"/"); snprintf(abs,sizeof abs,"%s/%s",cwd,arg); }
  size_t l=strlen(abs); while(l>1&&abs[l-1]=='/') abs[--l]=0;
  if (!strcmp(abs,"/")) { if(!opt_n){ snprintf(real,sizeof real,"%s",destroot);} walk("/", opt_n?"":destroot, "", 0,0,1); return; }
  snprintf(parent,sizeof parent,"%s",abs); char *sl=strrchr(parent,'/'); *sl=0; const char *name=sl+1;
  if (!opt_n) { if (mkdirs(parent,real,sizeof real)) { int e=errno; row(errstatus(e),abs,NULL,NULL,NULL,"-",-1,NULL,"cannot create destination directory"); return; } }
  else real[0]=0;
  walk(abs, real, name, 0,0,1);
}

int main(int argc, char **argv) {
  const char *metap=NULL, *listp=NULL; int c;
  const char *bodyp=NULL;
  while ((c=getopt(argc,argv,"RxFnDHt:s:e:M:L:o:B:V"))!=-1) switch(c){
    case 'D':opt_D=1;opt_n=1;break; case 'B':bodyp=optarg;break;
    case 'R':opt_R=1;break; case 'x':opt_x=1;break; case 'F':opt_F=1;break; case 'n':opt_n=1;break; case 'H':opt_H=1;break;
    case 't':opt_t=atoi(optarg);break; case 's':opt_s=strtoull(optarg,NULL,10);break;
    case 'e': excl=realloc(excl,(nexcl+1)*sizeof *excl); excl[nexcl++]=optarg; break;
    case 'M':metap=optarg;break; case 'L':listp=optarg;break; case 'o':snprintf(destroot,sizeof destroot,"%s",optarg);break;
    case 'V': printf("c0f-copy %s (C0F helper)\n",C0F_HELPER_VERSION); return 0;
    default: fprintf(stderr,"usage: c0f-copy [-R] [-x] [-F] [-n|-D] [-B BODYFILE] [-H] [-t SEC] [-s MAXBYTES] [-e EXCL]... [-M META.tsv] [-L LIST|-] -o DESTROOT [SRC...]\n"); return 2; }
  if (!opt_n && !*destroot) { fprintf(stderr,"c0f-copy: -o DESTROOT required (or -n for metadata only)\n"); return 2; }
  if (!opt_n) { size_t l=strlen(destroot); while(l>1&&destroot[l-1]=='/') destroot[--l]=0; if (mkdir(destroot,0700)&&errno!=EEXIST){ perror(destroot); return 2; } }
  buf=malloc(BUFSZ); if(!buf) return 2;
  if (bodyp) { BF=fopen(bodyp,"a"); if(!BF){ perror(bodyp); return 2; } }
  struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_handler=on_alarm; sigaction(SIGALRM,&sa,NULL); /* no SA_RESTART: read() gets EINTR */
  signal(SIGPIPE,SIG_IGN); signal(SIGXFSZ,SIG_IGN); /* RLIMIT_FSIZE: get EFBIG instead of being killed */
  int newfile=1; if (metap) { struct stat st; if(!stat(metap,&st)&&st.st_size>0) newfile=0; M=fopen(metap,"a"); if(!M){perror(metap);return 2;} } else M=stdout;
  if (newfile) fputs("status\tsource\tdest_rel\ttype\tsize\tmode\tuid\tgid\tinode\tnlink\tdev\tatime_utc\tmtime_utc\tctime_utc\tbtime_utc\tlink_target\tnoatime\tbytes_read\tsha256\tnote\n",M);
  if (listp) { FILE *L = strcmp(listp,"-")?fopen(listp,"r"):stdin; if(!L){perror(listp);return 2;}
    char line[PATH_MAX+2]; while (fgets(line,sizeof line,L)) { size_t l=strlen(line); while(l&&(line[l-1]=='\n'||line[l-1]=='\r')) line[--l]=0; if(l) { do_top(line); fflush(M);} } if(L!=stdin) fclose(L); }
  for (int i=optind;i<argc;i++) { do_top(argv[i]); fflush(M); }
  if (M!=stdout) fclose(M);
  if (BF) fclose(BF);
  fprintf(stderr,"c0f-copy: done ok=%lu failed=%lu\n",cnt_ok,cnt_fail);
  return cnt_fail?1:0;
}
