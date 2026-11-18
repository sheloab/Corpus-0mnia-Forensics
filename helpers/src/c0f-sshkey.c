/* SPDX-License-Identifier: MIT OR GPL-2.0-or-later
 * Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors */
/* c0f-sshkey: inventory SSH keys WITHOUT ssh-keygen and without ever printing secret material.
 * Usage: c0f-sshkey FILE...   (private keys, *.pub, authorized_keys, known_hosts, PuTTY .ppk)
 * TSV columns: file line kind key_type bits fp_sha256 fp_md5 encrypted cipher kdf kdf_rounds comment prefix note
 *   kind: openssh-private | pem-private | pkcs8-private | pkcs8-encrypted | putty-private | public
 *   prefix: options in authorized_keys (command=, from=, ...) or host patterns in known_hosts
 * Fingerprints match `ssh-keygen -l -E sha256|md5`. */
#include "c0f_common.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#ifndef O_NOATIME
#define O_NOATIME 01000000
#endif
#define MAXF (4*1024*1024)

typedef struct { const uint8_t *p; size_t n; } buf_t;
static int get_u32(buf_t *b, uint32_t *v){ if(b->n<4) return -1; *v=(uint32_t)b->p[0]<<24|(uint32_t)b->p[1]<<16|(uint32_t)b->p[2]<<8|b->p[3]; b->p+=4; b->n-=4; return 0; }
static int get_str(buf_t *b, buf_t *s){ uint32_t l; if(get_u32(b,&l)||l>b->n) return -1; s->p=b->p; s->n=l; b->p+=l; b->n-=l; return 0; }
static int mpint_bits(buf_t s){ size_t i=0; while(i<s.n&&s.p[i]==0) i++; if(i==s.n) return 0; int b=(int)(s.n-i-1)*8; uint8_t t=s.p[i]; while(t){b++;t>>=1;} return b; }

static const char *cur_file; static long cur_line;
static void out_row(const char *kind, const char *type, int bits, const char *fs, const char *fm, const char *enc, const char *cipher, const char *kdf, long rounds,
                    const char *comment, size_t clen, const char *prefix, size_t plen, const char *note){
  tsv_str(stdout,cur_file); printf("\t%ld\t%s\t",cur_line,kind); tsv_str(stdout,type?type:"-");
  if(bits>0) printf("\t%d",bits); else printf("\t-");
  printf("\t%s\t%s\t%s\t%s\t%s\t",fs?fs:"-",fm?fm:"-",enc?enc:"-",cipher?cipher:"-",kdf?kdf:"-"); if(rounds>=0) printf("%ld",rounds); else putchar('-');
  putchar('\t'); if(comment&&clen) tsv_put(stdout,comment,clen); else putchar('-');
  putchar('\t'); if(prefix&&plen) tsv_put(stdout,prefix,plen); else putchar('-');
  putchar('\t'); tsv_str(stdout,note&&*note?note:"-"); putchar('\n');
}
/* type, bits, fingerprints of a public key blob */
static int blob_info(const uint8_t *blob, size_t n, char *type, size_t tmax, int *bits, char *fs, char *fm){
  buf_t b={blob,n}, t; if(get_str(&b,&t)||t.n==0||t.n>=tmax) return -1; memcpy(type,t.p,t.n); type[t.n]=0; *bits=0;
  for(size_t i=0;i<t.n;i++) if(t.p[i]<0x21||t.p[i]>0x7e) return -1;
  buf_t x, y;
  if (!strncmp(type,"ssh-rsa",7)||!strncmp(type,"rsa-sha2",8)) { if(strstr(type,"-cert-")){ buf_t nonce; get_str(&b,&nonce);} if(!get_str(&b,&x)&&!get_str(&b,&y)) *bits=mpint_bits(y); }
  else if (!strncmp(type,"ssh-dss",7)) { if(strstr(type,"-cert-")){ buf_t nonce; get_str(&b,&nonce);} if(!get_str(&b,&x)) *bits=mpint_bits(x); }
  else if (strstr(type,"ed25519")) *bits=256;
  else if (strstr(type,"ed448")) *bits=456;
  else if (strstr(type,"nistp256")) *bits=256; else if (strstr(type,"nistp384")) *bits=384; else if (strstr(type,"nistp521")) *bits=521;
  uint8_t d[32]; sha256_ctx h; sha256_init(&h); sha256_update(&h,blob,n); sha256_final(&h,d); char b64[64]; b64_encode_nopad(d,32,b64); snprintf(fs,64,"SHA256:%s",b64);
  uint8_t m[16]; md5_ctx mc; md5_init(&mc); md5_update(&mc,blob,n); md5_final(&mc,m); int o=snprintf(fm,64,"MD5:"); for(int i=0;i<16;i++) o+=snprintf(fm+o,64-o,"%s%02x",i?":":"",m[i]);
  return 0;
}

/* ---- OpenSSH private key ---- */
static void openssh_priv(const uint8_t *raw, size_t rn){
  static const char magic[]="openssh-key-v1"; if(rn<sizeof magic||memcmp(raw,magic,sizeof magic)){ out_row("openssh-private",NULL,0,NULL,NULL,"unknown",NULL,NULL,-1,NULL,0,NULL,0,"bad magic"); return; }
  buf_t b={raw+sizeof magic, rn-sizeof magic}, ciph, kdf, kopt; uint32_t nk; long rounds=-1;
  if(get_str(&b,&ciph)||get_str(&b,&kdf)||get_str(&b,&kopt)||get_u32(&b,&nk)){ out_row("openssh-private",NULL,0,NULL,NULL,"unknown",NULL,NULL,-1,NULL,0,NULL,0,"truncated"); return; }
  char cs[64], ks[64]; snprintf(cs,sizeof cs,"%.*s",(int)ciph.n,ciph.p); snprintf(ks,sizeof ks,"%.*s",(int)kdf.n,kdf.p);
  if (kopt.n){ buf_t ko=kopt, salt; uint32_t r; if(!get_str(&ko,&salt)&&!get_u32(&ko,&r)) rounds=r; }
  int enc = strcmp(cs,"none")!=0;
  buf_t pubs[16]; uint32_t np = nk>16?16:nk; for(uint32_t i=0;i<np;i++) if(get_str(&b,&pubs[i])) { np=i; break; }
  buf_t priv; int havepriv = !get_str(&b,&priv);
  /* comments are only readable when the private section is not encrypted */
  buf_t comments[16]; int haveC[16]={0};
  if (!enc && havepriv) { buf_t pv=priv; uint32_t c1,c2; if(!get_u32(&pv,&c1)&&!get_u32(&pv,&c2)&&c1==c2) for(uint32_t i=0;i<np;i++){
      buf_t t; if(get_str(&pv,&t)) break; char ty[96]; snprintf(ty,sizeof ty,"%.*s",(int)t.n,t.p); int nf;
      if (strstr(ty,"-cert-")) nf=2; /* cert blob + private part handled roughly below */
      if (!strcmp(ty,"ssh-ed25519")) nf=2; else if(!strcmp(ty,"ssh-rsa")) nf=6; else if(!strcmp(ty,"ssh-dss")) nf=5;
      else if(!strncmp(ty,"ecdsa-sha2-",11)) nf=3; else if(!strcmp(ty,"sk-ssh-ed25519@openssh.com")) nf=-1; else if(!strncmp(ty,"sk-ecdsa-sha2-",14)) nf=-2; else nf=0;
      int ok=1; buf_t s; uint8_t fl;
      if (nf>0) { for(int k=0;k<nf;k++) if(get_str(&pv,&s)){ok=0;break;} }
      else if (nf==-1) { if(get_str(&pv,&s)||get_str(&pv,&s)||pv.n<1) ok=0; else { fl=pv.p[0]; (void)fl; pv.p++; pv.n--; if(get_str(&pv,&s)||get_str(&pv,&s)) ok=0; } }
      else if (nf==-2) { if(get_str(&pv,&s)||get_str(&pv,&s)||get_str(&pv,&s)||pv.n<1) ok=0; else { pv.p++; pv.n--; if(get_str(&pv,&s)||get_str(&pv,&s)) ok=0; } }
      else ok=0;
      if(!ok) break; if(!get_str(&pv,&comments[i])) haveC[i]=1; else break; } }
  if (np==0) out_row("openssh-private",NULL,0,NULL,NULL,enc?"yes":"no",cs,ks,rounds,NULL,0,NULL,0,"no public key in file");
  for (uint32_t i=0;i<np;i++){ char ty[96], fs[64], fm[64]; int bits;
    if (blob_info(pubs[i].p,pubs[i].n,ty,sizeof ty,&bits,fs,fm)) { out_row("openssh-private",NULL,0,NULL,NULL,enc?"yes":"no",cs,ks,rounds,NULL,0,NULL,0,"unparsable public blob"); continue; }
    out_row("openssh-private",ty,bits,fs,fm,enc?"yes":"no (NO PASSPHRASE)",cs,ks,rounds,haveC[i]?(const char*)comments[i].p:NULL,haveC[i]?comments[i].n:0,NULL,0,enc?"comment hidden (encrypted)":NULL); }
}

/* ---- minimal DER reader (for PEM / PKCS#8 unencrypted keys -> public blob) ---- */
static int der(buf_t *b, int *tag, buf_t *v){ if(b->n<2) return -1; *tag=b->p[0]; size_t l=b->p[1], h=2;
  if (l&0x80){ int k=l&0x7f; if(k<1||k>4||b->n<2+(size_t)k) return -1; l=0; for(int i=0;i<k;i++) l=(l<<8)|b->p[2+i]; h=2+k; }
  if (l>b->n-h) return -1; v->p=b->p+h; v->n=l; b->p+=h+l; b->n-=h+l; return 0; }
static size_t put_str(uint8_t *o, const void *s, size_t n){ o[0]=n>>24;o[1]=n>>16;o[2]=n>>8;o[3]=n; memcpy(o+4,s,n); return 4+n; }
static size_t put_mpint(uint8_t *o, buf_t x){ while(x.n>1&&x.p[0]==0&&!(x.p[1]&0x80)){x.p++;x.n--;} if(x.n&&(x.p[0]&0x80)){ size_t n=x.n+1; o[0]=n>>24;o[1]=n>>16;o[2]=n>>8;o[3]=n;o[4]=0; memcpy(o+5,x.p,x.n); return 5+x.n;} return put_str(o,x.p,x.n); }
static const uint8_t OID_P256[]={0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07}, OID_P384[]={0x2b,0x81,0x04,0x00,0x22}, OID_P521[]={0x2b,0x81,0x04,0x00,0x23};
static const char *curve_of(buf_t oid){ if(oid.n==sizeof OID_P256&&!memcmp(oid.p,OID_P256,oid.n)) return "nistp256"; if(oid.n==sizeof OID_P384&&!memcmp(oid.p,OID_P384,oid.n)) return "nistp384"; if(oid.n==sizeof OID_P521&&!memcmp(oid.p,OID_P521,oid.n)) return "nistp521"; return NULL; }
static void emit_blob(const char *kind, uint8_t *blob, size_t n, const char *note){ char ty[96],fs[64],fm[64]; int bits; if(blob_info(blob,n,ty,sizeof ty,&bits,fs,fm)) out_row(kind,NULL,0,NULL,NULL,"no (NO PASSPHRASE)",NULL,NULL,-1,NULL,0,NULL,0,"cannot derive public key");
  else out_row(kind,ty,bits,fs,fm,"no (NO PASSPHRASE)",NULL,NULL,-1,NULL,0,NULL,0,note); }
static void rsa_pkcs1(const char *kind, buf_t seq){ int t; buf_t v, n, e; buf_t s=seq; if(der(&s,&t,&v)||der(&s,&t,&n)||der(&s,&t,&e)) { emit_blob(kind,NULL,0,NULL); return; }
  uint8_t *bl=malloc(32+n.n+e.n); size_t o=put_str(bl,"ssh-rsa",7); o+=put_mpint(bl+o,e); o+=put_mpint(bl+o,n); emit_blob(kind,bl,o,NULL); free(bl); }
static void ec_sec1(const char *kind, buf_t seq, const char *curve_hint){ int t; buf_t v, s=seq, ver, priv; const char *curve=curve_hint; buf_t pub={0,0};
  if(der(&s,&t,&ver)||der(&s,&t,&priv)) { emit_blob(kind,NULL,0,NULL); return; }
  while(s.n){ if(der(&s,&t,&v)) break; buf_t in=v, x; int t2; if(t==0xa0&&!der(&in,&t2,&x)&&t2==6) curve=curve_of(x)?curve_of(x):curve; if(t==0xa1&&!der(&in,&t2,&x)&&t2==3&&x.n>1){ pub.p=x.p+1; pub.n=x.n-1; } }
  if(!curve||!pub.n){ out_row(kind,"ecdsa",0,NULL,NULL,"no (NO PASSPHRASE)",NULL,NULL,-1,NULL,0,NULL,0,"public point or curve absent"); return; }
  char ty[64]; snprintf(ty,sizeof ty,"ecdsa-sha2-%s",curve); uint8_t *bl=malloc(64+pub.n); size_t o=put_str(bl,ty,strlen(ty)); o+=put_str(bl+o,curve,strlen(curve)); o+=put_str(bl+o,pub.p,pub.n); emit_blob(kind,bl,o,NULL); free(bl); }
static void dsa_der(const char *kind, buf_t seq){ int t; buf_t s=seq, v, p,q,g,y; if(der(&s,&t,&v)||der(&s,&t,&p)||der(&s,&t,&q)||der(&s,&t,&g)||der(&s,&t,&y)){ emit_blob(kind,NULL,0,NULL); return; }
  uint8_t *bl=malloc(64+p.n+q.n+g.n+y.n); size_t o=put_str(bl,"ssh-dss",7); o+=put_mpint(bl+o,p); o+=put_mpint(bl+o,q); o+=put_mpint(bl+o,g); o+=put_mpint(bl+o,y); emit_blob(kind,bl,o,NULL); free(bl); }

static void pem(const char *label, const char *body, size_t blen, int encrypted_hdr, const char *dek){
  uint8_t *raw=malloc(blen); long rn=-1;
  /* skip RFC1421 headers (Proc-Type/DEK-Info) */
  const char *b=body; const char *hdr_end=strstr(body,"\n\n"); if(!hdr_end) hdr_end=strstr(body,"\r\n\r\n"); if(hdr_end && (size_t)(hdr_end-body)<blen && memchr(body,':',hdr_end-body)) b=hdr_end;
  rn=b64_decode(b,blen-(size_t)(b-body),raw,blen);
  if (!strcmp(label,"OPENSSH PRIVATE KEY")) { if(rn>0) openssh_priv(raw,(size_t)rn); else out_row("openssh-private",NULL,0,NULL,NULL,"unknown",NULL,NULL,-1,NULL,0,NULL,0,"base64 error"); }
  else if (!strcmp(label,"ENCRYPTED PRIVATE KEY")) out_row("pkcs8-encrypted",NULL,0,NULL,NULL,"yes",NULL,NULL,-1,NULL,0,NULL,0,"PKCS#8 encrypted: type hidden");
  else if (encrypted_hdr) { const char *ty=!strncmp(label,"RSA",3)?"ssh-rsa":!strncmp(label,"DSA",3)?"ssh-dss":!strncmp(label,"EC",2)?"ecdsa":label; out_row("pem-private",ty,0,NULL,NULL,"yes",dek,NULL,-1,NULL,0,NULL,0,"legacy PEM encryption"); }
  else if (rn>0) { buf_t all={raw,(size_t)rn}, seq; int t;
    if (der(&all,&t,&seq)||t!=0x30) out_row("pem-private",NULL,0,NULL,NULL,"no (NO PASSPHRASE)",NULL,NULL,-1,NULL,0,NULL,0,"DER parse error");
    else if (!strcmp(label,"RSA PRIVATE KEY")) rsa_pkcs1("pem-private",seq);
    else if (!strcmp(label,"EC PRIVATE KEY")) ec_sec1("pem-private",seq,NULL);
    else if (!strcmp(label,"DSA PRIVATE KEY")) dsa_der("pem-private",seq);
    else if (!strcmp(label,"PRIVATE KEY")) { buf_t s=seq, ver, alg, key, oid, par={0,0}; int t2;
      if(der(&s,&t,&ver)||der(&s,&t,&alg)||der(&s,&t,&key)) { out_row("pkcs8-private",NULL,0,NULL,NULL,"no (NO PASSPHRASE)",NULL,NULL,-1,NULL,0,NULL,0,"DER parse error"); }
      else { buf_t a=alg; der(&a,&t2,&oid); if(a.n) der(&a,&t2,&par); buf_t in=key, inner;
        static const uint8_t RSA[]={0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01}, EC[]={0x2a,0x86,0x48,0xce,0x3d,0x02,0x01}, DSA[]={0x2a,0x86,0x48,0xce,0x38,0x04,0x01}, ED[]={0x2b,0x65,0x70};
        if (oid.n==sizeof RSA&&!memcmp(oid.p,RSA,oid.n)&&!der(&in,&t2,&inner)) rsa_pkcs1("pkcs8-private",inner);
        else if (oid.n==sizeof EC&&!memcmp(oid.p,EC,oid.n)&&!der(&in,&t2,&inner)) ec_sec1("pkcs8-private",inner,par.n?curve_of(par):NULL);
        else if (oid.n==sizeof DSA&&!memcmp(oid.p,DSA,oid.n)) out_row("pkcs8-private","ssh-dss",0,NULL,NULL,"no (NO PASSPHRASE)",NULL,NULL,-1,NULL,0,NULL,0,"public value not stored in PKCS#8 DSA");
        else if (oid.n==sizeof ED&&!memcmp(oid.p,ED,oid.n)) out_row("pkcs8-private","ssh-ed25519",256,NULL,NULL,"no (NO PASSPHRASE)",NULL,NULL,-1,NULL,0,NULL,0,"fingerprint needs Ed25519 math (not derived)");
        else out_row("pkcs8-private",NULL,0,NULL,NULL,"no (NO PASSPHRASE)",NULL,NULL,-1,NULL,0,NULL,0,"unknown algorithm OID"); } }
    else out_row("pem-private",label,0,NULL,NULL,"unknown",NULL,NULL,-1,NULL,0,NULL,0,"unsupported PEM label"); }
  else out_row("pem-private",label,0,NULL,NULL,"unknown",NULL,NULL,-1,NULL,0,NULL,0,"base64 error");
  free(raw);
}

/* ---- PuTTY .ppk ---- */
static void ppk(char *txt){
  char ty[96]="-", enc[64]="-", com[1024]=""; size_t clen=0; uint8_t *blob=NULL; long bn=-1; char *line=strtok(txt,"\n");
  while (line) { size_t l=strlen(line); if(l&&line[l-1]=='\r') line[--l]=0;
    if (!strncmp(line,"PuTTY-User-Key-File-",20)) { char *c=strchr(line,':'); if(c){ c++; while(*c==' ')c++; snprintf(ty,sizeof ty,"%s",c);} }
    else if (!strncmp(line,"Encryption:",11)) { char *c=line+11; while(*c==' ')c++; snprintf(enc,sizeof enc,"%s",c); }
    else if (!strncmp(line,"Comment:",8)) { char *c=line+8; while(*c==' ')c++; clen=strlen(c); if(clen>=sizeof com) clen=sizeof com-1; memcpy(com,c,clen); }
    else if (!strncmp(line,"Public-Lines:",13)) { int nl=atoi(line+13); size_t cap=(size_t)nl*80+4; char *acc=calloc(1,cap); size_t al=0;
      for(int i=0;i<nl;i++){ char *x=strtok(NULL,"\n"); if(!x) break; size_t xl=strlen(x); if(al+xl<cap){ memcpy(acc+al,x,xl); al+=xl;} }
      blob=malloc(al+1); bn=b64_decode(acc,al,blob,al+1); free(acc); }
    line=strtok(NULL,"\n"); }
  char t2[96], fs[64], fm[64]; int bits=0; int isenc=strcmp(enc,"none")!=0;
  if (blob && bn>0 && !blob_info(blob,(size_t)bn,t2,sizeof t2,&bits,fs,fm)) out_row("putty-private",t2,bits,fs,fm,isenc?"yes":"no (NO PASSPHRASE)",enc,NULL,-1,com,clen,NULL,0,NULL);
  else out_row("putty-private",ty,0,NULL,NULL,isenc?"yes":"no (NO PASSPHRASE)",enc,NULL,-1,com,clen,NULL,0,"public lines unreadable");
  free(blob);
}

/* ---- public key lines: authorized_keys / *.pub / known_hosts ---- */
static int keytype_token(const char *s, size_t n){ static const char *k[]={"ssh-rsa","ssh-dss","ssh-ed25519","ssh-ed448","ecdsa-sha2-","sk-ssh-ed25519","sk-ecdsa-sha2-","rsa-sha2-",NULL};
  for(int i=0;k[i];i++){ size_t l=strlen(k[i]); if(n>=l&&!strncmp(s,k[i],l)) return 1; } return 0; }
static void pubfile(char *txt, int known){
  char *save=NULL; cur_line=0; long rows=0;
  for (char *line=strtok_r(txt,"\n",&save); line; line=strtok_r(NULL,"\n",&save)) { cur_line++;
    size_t l=strlen(line); if(l&&line[l-1]=='\r') line[--l]=0; char *p=line; while(*p==' '||*p=='\t') p++; if(!*p||*p=='#') continue;
    /* tokenize honoring double quotes; find "<keytype> <base64>" */
    char *q=p; int inq=0; char *kt=NULL;
    while (*q) { if(!inq && (q==p||q[-1]==' '||q[-1]=='\t') && keytype_token(q,strlen(q))) { kt=q; break; } if(*q=='"') inq=!inq; q++; }
    if (!kt) { out_row("public",NULL,0,NULL,NULL,"-",NULL,NULL,-1,NULL,0,p,strlen(p),"unrecognised line"); rows++; continue; }
    size_t pl=(size_t)(kt-p); while(pl&&(p[pl-1]==' '||p[pl-1]=='\t')) pl--;
    char *sp=kt+strcspn(kt," \t"); char tytok[96]; snprintf(tytok,sizeof tytok,"%.*s",(int)(sp-kt),kt); while(*sp==' '||*sp=='\t') sp++;
    size_t bl=strcspn(sp," \t"); char *com=sp+bl; while(*com==' '||*com=='\t') com++;
    uint8_t *blob=malloc(bl+1); long bn=b64_decode(sp,bl,blob,bl+1); char ty[96],fs[64],fm[64]; int bits; char note[256]="";
    if (bn<=0||blob_info(blob,(size_t)bn,ty,sizeof ty,&bits,fs,fm)) { out_row("public",tytok,0,NULL,NULL,"-",NULL,NULL,-1,com,strlen(com),p,pl,"base64/blob error"); free(blob); rows++; continue; }
    if (strcmp(ty,tytok)) snprintf(note,sizeof note,"type token '%s' differs from blob type",tytok);
    if (known && pl && !strncmp(p,"|1|",3)) { size_t k=strlen(note); snprintf(note+k,sizeof note-k,"%shashed hostname",k?"; ":""); }
    if (!known && pl) { const char *flags[]={"command=","from=","permitopen=","permitlisten=","environment=","tunnel=","principals=","cert-authority","no-pty","restrict",NULL};
      for(int i=0;flags[i];i++){ char tmp[1024]; snprintf(tmp,sizeof tmp,"%.*s",(int)(pl<sizeof tmp-1?pl:sizeof tmp-1),p); if(strstr(tmp,flags[i])){ size_t k=strlen(note); snprintf(note+k,sizeof note-k,"%soption %s",k?"; ":"",flags[i]); } } }
    out_row(known?"known_host":"public",ty,bits,fs,fm,"-",NULL,NULL,-1,com,strlen(com),p,pl,note); rows++; free(blob);
  }
  if (!rows) { cur_line=0; out_row("public",NULL,0,NULL,NULL,"-",NULL,NULL,-1,NULL,0,NULL,0,"no key lines"); }
}

static void one(const char *f){
  cur_file=f; cur_line=0;
  int fd=open(f,O_RDONLY|O_CLOEXEC|O_NOATIME|O_NOFOLLOW|O_NONBLOCK); if(fd<0&&errno==EPERM) fd=open(f,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
  if (fd<0) { char e[128]; snprintf(e,sizeof e,"open: %s",strerror(errno)); out_row("error",NULL,0,NULL,NULL,"-",NULL,NULL,-1,NULL,0,NULL,0,e); return; }
  struct stat st; if (fstat(fd,&st)||!S_ISREG(st.st_mode)) { close(fd); out_row("error",NULL,0,NULL,NULL,"-",NULL,NULL,-1,NULL,0,NULL,0,"not a regular file"); return; }
  char *txt=malloc(MAXF+1); ssize_t n=0, r; while(n<MAXF && (r=read(fd,txt+n,MAXF-n))>0) n+=r; close(fd); if(n<0) n=0; txt[n]=0;
  if (memchr(txt,0,(size_t)n)) { out_row("error",NULL,0,NULL,NULL,"-",NULL,NULL,-1,NULL,0,NULL,0,"binary file, not an SSH key"); free(txt); return; }
  char *b=strstr(txt,"-----BEGIN ");
  if (b) { int found=0;
    while (b) { char *le=strstr(b+11,"-----"); if(!le) break; char label[64]; snprintf(label,sizeof label,"%.*s",(int)(le-(b+11)),b+11);
      char endm[96]; snprintf(endm,sizeof endm,"-----END %s-----",label); char *body=le+5; char *e=strstr(body,endm); if(!e) break;
      for(char *c=txt;c<b;c++) if(*c=='\n') cur_line++; cur_line++;
      int enchdr=0; char dek[64]="-"; char *pt=strstr(body,"Proc-Type:"); if(pt&&pt<e&&strstr(pt,"ENCRYPTED")&&strstr(pt,"ENCRYPTED")<e) enchdr=1;
      char *dk=strstr(body,"DEK-Info:"); if(dk&&dk<e){ dk+=9; while(*dk==' ')dk++; size_t l=strcspn(dk,",\r\n"); snprintf(dek,sizeof dek,"%.*s",(int)l,dk); }
      if (strstr(label,"PRIVATE KEY")) { pem(label,body,(size_t)(e-body),enchdr,dek); found=1; }
      else if (strstr(label,"PUBLIC KEY")) { out_row("pem-public",label,0,NULL,NULL,"-",NULL,NULL,-1,NULL,0,NULL,0,"PEM public key (not SSH wire format)"); found=1; }
      cur_line=0; b=strstr(e,"-----BEGIN "); }
    if (!found) out_row("error",NULL,0,NULL,NULL,"-",NULL,NULL,-1,NULL,0,NULL,0,"PEM block without key");
  }
  else if (!strncmp(txt,"PuTTY-User-Key-File-",20)) ppk(txt);
  else { const char *base=strrchr(f,'/'); base=base?base+1:f; pubfile(txt, strstr(base,"known_hosts")!=NULL); }
  free(txt);
}

int main(int argc, char **argv){
  if (argc>1&&!strcmp(argv[1],"-V")) { printf("c0f-sshkey %s (C0F helper)\n",C0F_HELPER_VERSION); return 0; }
  if (argc<2) { fprintf(stderr,"usage: c0f-sshkey FILE...\n"); return 2; }
  printf("file\tline\tkind\tkey_type\tbits\tfp_sha256\tfp_md5\tencrypted\tcipher\tkdf\tkdf_rounds\tcomment\tprefix\tnote\n");
  for (int i=1;i<argc;i++) one(argv[i]);
  return 0;
}
