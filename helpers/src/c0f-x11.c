/* SPDX-License-Identifier: MIT OR GPL-2.0-or-later
 * Copyright (c) 2026 Corpus-0mnia Forensics (C0F) authors */
/* c0f-x11: minimal X11 protocol client for live response (no Xlib, static, read-mostly).
 * Usage: c0f-x11 [-d DISPLAY] [-a XAUTHORITY] [-r ROOTPREFIX] [-t SEC] info|windows|clipboard OUTDIR|screenshot OUT.png
 *   DISPLAY: ":10", ":10.0", "unix:10", "localhost:10" (TCP 6000+N, e.g. SSH X11 forwarding) or a socket path.
 *   ROOTPREFIX: prepend to the socket path (e.g. /proc/PID/root for a session inside a container).
 * Footprint on the X server: creates ONE InputOnly window (clipboard mode only, destroyed at exit). Atom lookups use
 * only-if-exists; the standard ICCCM atoms CLIPBOARD/TARGETS/TIMESTAMP/INCR/UTF8_STRING are created only when missing
 * (reported on stderr). Reading a selection asks the owning application to send its data. Owner/window PIDs come from
 * the X-Resource extension (client PID) and _NET_WM_PID (set by the application itself, can be forged). */
#include "c0f_common.h"
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <ctype.h>
#include <signal.h>
#include <stddef.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int xfd=-1, tmo=15000; static uint16_t seq;
static uint32_t idbase, idmask, root, root_visual, rmask, gmask, bmask; static int root_depth, bpp, scanpad, img_lsb=1; static uint16_t sw, sh;
static char vendor[256]; static uint32_t release;
static int last_err, last_err_seq;

static void die(int code, const char *m){ fprintf(stderr,"c0f-x11: %s\n",m); exit(code); }
static int wr_all(const void *b, size_t n){ const uint8_t *p=b; while(n){ ssize_t r=write(xfd,p,n); if(r<0){ if(errno==EINTR) continue; return -1;} p+=r; n-=(size_t)r;} return 0; }
static int rd_all(void *b, size_t n){ uint8_t *p=b; while(n){ struct pollfd pf={xfd,POLLIN,0}; int pr=poll(&pf,1,tmo); if(pr==0){ errno=ETIMEDOUT; return -1;} if(pr<0){ if(errno==EINTR) continue; return -1;}
    ssize_t r=read(xfd,p,n); if(r<0){ if(errno==EINTR) continue; return -1;} if(r==0){ errno=ECONNRESET; return -1;} p+=r; n-=(size_t)r;} return 0; }
static uint32_t g32(const uint8_t *p){ return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static uint16_t g16(const uint8_t *p){ return (uint16_t)(p[0]|p[1]<<8); }
static void p32(uint8_t *p, uint32_t v){ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void p16(uint8_t *p, uint16_t v){ p[0]=v; p[1]=v>>8; }

/* ---- events ---- */
typedef struct { uint8_t b[32]; } ev_t; static ev_t evq[512]; static int evn;
static void queue_ev(const uint8_t *b){ if(evn<512) memcpy(evq[evn++].b,b,32); }

static void send_req(const uint8_t *b, size_t n){ if(wr_all(b,n)) die(4,"write to X server failed"); seq++; }
/* wait for the reply to request number want; returns malloc'd buffer (32+extra) or NULL on X error */
static uint8_t *reply(uint16_t want){
  for(;;){ uint8_t h[32]; if(rd_all(h,32)) die(4, errno==ETIMEDOUT?"timeout waiting for X server":"X connection lost");
    uint16_t s=g16(h+2);
    if (h[0]==0) { last_err=h[1]; last_err_seq=s; if(s==want) return NULL; continue; }
    if (h[0]==1) { uint32_t len=g32(h+4); uint8_t *r=malloc(32+(size_t)len*4); if(!r) die(4,"out of memory"); memcpy(r,h,32); if(len&&rd_all(r+32,(size_t)len*4)) die(4,"X connection lost"); if(s==want) return r; free(r); continue; }
    if ((h[0]&0x7f)==35) { uint32_t len=g32(h+4); uint8_t *skip=malloc((size_t)len*4+1); if(len) rd_all(skip,(size_t)len*4); free(skip); continue; } /* GenericEvent */
    queue_ev(h); }
}
static void sync_x(void){ uint8_t r[4]={43,0,1,0}; send_req(r,4); free(reply(seq)); } /* GetInputFocus as round trip */

static uint32_t atom_x(const char *name, int only_if_exists){ size_t n=strlen(name), pad=(4-n%4)%4; uint8_t *r=calloc(1,8+n+pad); r[0]=16; r[1]=(uint8_t)only_if_exists; p16(r+2,(uint16_t)((8+n+pad)/4)); p16(r+4,(uint16_t)n); memcpy(r+8,name,n);
  send_req(r,8+n+pad); free(r); uint8_t *rp=reply(seq); uint32_t a=rp?g32(rp+8):0; free(rp); return a; }
static uint32_t atom(const char *name){ return atom_x(name,1); }
static int interned; /* standard ICCCM atoms we had to create */
static uint32_t atom_std(const char *name){ uint32_t a=atom_x(name,1); if(!a){ a=atom_x(name,0); if(a) interned++; } return a; }
static char *atom_name(uint32_t a){ uint8_t r[8]={17,0,2,0}; p32(r+4,a); send_req(r,8); uint8_t *rp=reply(seq); if(!rp) return strdup("?"); uint16_t n=g16(rp+8); char *s=malloc(n+1); memcpy(s,rp+32,n); s[n]=0; free(rp); return s; }
/* GetProperty: returns data (malloc) and fills type/format/nitems; reads everything in chunks */
static uint8_t *getprop(uint32_t win, uint32_t prop, int del, uint32_t *type, int *format, size_t *nbytes){
  size_t cap=0, n=0; uint8_t *out=NULL; uint32_t off=0; *type=0; *format=0;
  for(;;){ uint8_t r[24]={20,0,6,0}; r[1]=0; p32(r+4,win); p32(r+8,prop); p32(r+12,0); p32(r+16,off); p32(r+20,262144); send_req(r,24);
    uint8_t *rp=reply(seq); if(!rp){ free(out); return NULL; }
    *format=rp[1]; *type=g32(rp+8); uint32_t after=g32(rp+12), items=g32(rp+16); size_t bytes=(size_t)items*(*format/8);
    if (n+bytes+1>cap){ cap=(n+bytes+1)*2; out=realloc(out,cap); }
    memcpy(out+n,rp+32,bytes); n+=bytes; free(rp);
    if (!*type || !after) break; off+= (uint32_t)(bytes/4); }
  if (del) { uint8_t r[12]={19,0,3,0}; p32(r+4,win); p32(r+8,prop); send_req(r,12); }
  if (!out) out=calloc(1,1); out[n]=0; *nbytes=n; return out;
}

/* ---- connection ---- */
static int parse_disp(const char *d, char *host, size_t hl, int *num){ const char *c=strrchr(d,':'); if(!c) { *num=atoi(d); host[0]=0; return 0; }
  snprintf(host,hl,"%.*s",(int)(c-d),d); *num=atoi(c+1); return 0; }
static void read_cookie(const char *file, int num, uint8_t *cookie, int *clen){
  *clen=0; FILE *f=fopen(file,"rb"); if(!f){ fprintf(stderr,"c0f-x11: cannot read %s: %s (trying without auth)\n",file,strerror(errno)); return; }
  char want[16]; snprintf(want,sizeof want,"%d",num);
  for(;;){ uint8_t h[2]; if(fread(h,1,2,f)!=2) break; uint8_t *fld[4]; uint16_t len[4]; int ok=1;
    for(int i=0;i<4;i++){ uint8_t l[2]; if(fread(l,1,2,f)!=2){ok=0;break;} len[i]=(uint16_t)(l[0]<<8|l[1]); fld[i]=malloc(len[i]+1); if(fread(fld[i],1,len[i],f)!=len[i]){ok=0; free(fld[i]); break;} fld[i][len[i]]=0; }
    if(!ok) break;
    int match = len[1]==strlen(want) && !memcmp(fld[1],want,len[1]) && len[2]==18 && !memcmp(fld[2],"MIT-MAGIC-COOKIE-1",18) && len[3]==16;
    if (match && !*clen) { memcpy(cookie,fld[3],16); *clen=16; }
    for(int i=0;i<4;i++) free(fld[i]); }
  fclose(f); if(!*clen) fprintf(stderr,"c0f-x11: no MIT-MAGIC-COOKIE-1 for display %d in %s (trying without auth)\n",num,file);
}
static void xconnect(const char *disp, const char *auth, const char *rootpfx){
  char host[256]; int num=0;
  if (disp[0]=='/') { struct sockaddr_un sa; memset(&sa,0,sizeof sa); sa.sun_family=AF_UNIX; snprintf(sa.sun_path,sizeof sa.sun_path,"%s%s",rootpfx?rootpfx:"",disp);
    const char *x=strrchr(disp,'X'); num=x?atoi(x+1):0; xfd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0); if(connect(xfd,(void*)&sa,sizeof sa)) die(3,"cannot connect to socket path"); }
  else { parse_disp(disp,host,sizeof host,&num);
    if (!host[0] || !strcmp(host,"unix")) { struct sockaddr_un sa; memset(&sa,0,sizeof sa); sa.sun_family=AF_UNIX;
      snprintf(sa.sun_path,sizeof sa.sun_path,"%s/tmp/.X11-unix/X%d",rootpfx?rootpfx:"",num); xfd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
      if (connect(xfd,(void*)&sa,sizeof sa)) { if(rootpfx&&*rootpfx) die(3,"cannot connect to X socket"); /* abstract namespace */
        close(xfd); xfd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0); memset(&sa,0,sizeof sa); sa.sun_family=AF_UNIX; int l=snprintf(sa.sun_path+1,sizeof sa.sun_path-1,"/tmp/.X11-unix/X%d",num);
        if (connect(xfd,(void*)&sa,(socklen_t)(offsetof(struct sockaddr_un,sun_path)+1+l))) die(3,"cannot connect to X socket (path or abstract)"); } }
    else if (!strcmp(host,"localhost")||!strcmp(host,"127.0.0.1")) { struct sockaddr_in si; memset(&si,0,sizeof si); si.sin_family=AF_INET; si.sin_port=htons((uint16_t)(6000+num)); si.sin_addr.s_addr=htonl(0x7f000001);
      xfd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); if(connect(xfd,(void*)&si,sizeof si)) die(3,"cannot connect to TCP display"); }
    else die(2,"only local displays are supported"); }
  uint8_t cookie[16]; int clen=0; if(auth) read_cookie(auth,num,cookie,&clen);
  uint8_t s[12+20+16]; memset(s,0,sizeof s); s[0]='l'; p16(s+2,11); p16(s+4,0); size_t sl=12;
  if (clen) { p16(s+6,18); p16(s+8,16); memcpy(s+12,"MIT-MAGIC-COOKIE-1",18); memcpy(s+32,cookie,16); sl=48; }
  if (wr_all(s,sl)) die(3,"setup write failed");
  uint8_t h[8]; if(rd_all(h,8)) die(3,"no setup reply"); uint16_t extra=g16(h+6); uint8_t *d=malloc((size_t)extra*4+1); if(rd_all(d,(size_t)extra*4)) die(3,"short setup reply");
  if (h[0]!=1) { char m[300]; snprintf(m,sizeof m,"X server refused connection: %.*s",h[1],(char*)d); die(3,m); }
  release=g32(d); idbase=g32(d+4); idmask=g32(d+8); uint16_t vl=g16(d+16); int nscr=d[20], nfmt=d[21]; img_lsb = d[22]==0;
  snprintf(vendor,sizeof vendor,"%.*s",vl,(char*)d+32); size_t o=32+vl+((4-vl%4)%4);
  int fmt_depth[64],fmt_bpp[64],fmt_pad[64]; for(int i=0;i<nfmt&&i<64;i++){ fmt_depth[i]=d[o]; fmt_bpp[i]=d[o+1]; fmt_pad[i]=d[o+2]; o+=8; }
  if (nscr<1) die(4,"no screens");
  root=g32(d+o); sw=g16(d+o+20); sh=g16(d+o+22); root_visual=g32(d+o+32); root_depth=d[o+38]; int ndep=d[o+39]; o+=40;
  for(int i=0;i<ndep;i++){ int nv=g16(d+o+2); o+=8; for(int k=0;k<nv;k++){ if(g32(d+o)==root_visual){ rmask=g32(d+o+8); gmask=g32(d+o+12); bmask=g32(d+o+16);} o+=24; } }
  for(int i=0;i<nfmt&&i<64;i++) if(fmt_depth[i]==root_depth){ bpp=fmt_bpp[i]; scanpad=fmt_pad[i]; }
  free(d);
}

/* ---- X-Resource extension: PID of the client that owns a window ---- */
static int xres_op=-1;
static void xres_init(void){ const char *nm="X-Resource"; size_t n=strlen(nm), pad=(4-n%4)%4; uint8_t r[8+16]; memset(r,0,sizeof r); r[0]=98; p16(r+2,(uint16_t)((8+n+pad)/4)); p16(r+4,(uint16_t)n); memcpy(r+8,nm,n);
  send_req(r,8+n+pad); uint8_t *rp=reply(seq); if(rp&&rp[8]) xres_op=rp[9]; free(rp); }
static long client_pid(uint32_t win){ if(xres_op<0||!win) return -1; uint8_t r[16]; r[0]=(uint8_t)xres_op; r[1]=4; p16(r+2,4); p32(r+4,1); p32(r+8,win); p32(r+12,2 /*LocalClientPIDMask*/);
  send_req(r,16); uint8_t *rp=reply(seq); long pid=-1; if(rp){ uint32_t nid=g32(rp+8); size_t o=32; for(uint32_t i=0;i<nid;i++){ uint32_t mask=g32(rp+o+4), len=g32(rp+o+8); if(mask==2&&len==4) pid=(long)g32(rp+o+12); o+=12+len; } free(rp);} return pid; }

/* ---- window properties ---- */
static uint32_t A_NET_WM_PID, A_NET_WM_NAME, A_NET_CLIENT_LIST, A_NET_ACTIVE, A_CLIENT_LEADER;
static long prop_card(uint32_t w, uint32_t a){ if(!a) return -1; uint32_t t; int f; size_t n; uint8_t *v=getprop(w,a,0,&t,&f,&n); long r=(v&&f==32&&n>=4)?(long)g32(v):-1; free(v); return r; }
static void put_prop_text(uint32_t w, uint32_t a){ uint32_t t; int f; size_t n; uint8_t *v= a?getprop(w,a,0,&t,&f,&n):NULL; if(v&&n&&f==8){ for(size_t i=0;i<n;i++) if(!v[i]) v[i]='|'; while(n&&v[n-1]=='|') n--; tsv_put(stdout,(char*)v,n);} else putchar('-'); free(v); }
static uint32_t *client_list(size_t *cnt){ uint32_t t; int f; size_t n; *cnt=0; if(!A_NET_CLIENT_LIST) return NULL; uint8_t *v=getprop(root,A_NET_CLIENT_LIST,0,&t,&f,&n); if(!v||f!=32){ free(v); return NULL; } *cnt=n/4; return (uint32_t*)v; }

static void do_windows(void){
  A_NET_WM_PID=atom("_NET_WM_PID"); A_NET_WM_NAME=atom("_NET_WM_NAME"); A_NET_CLIENT_LIST=atom("_NET_CLIENT_LIST"); A_NET_ACTIVE=atom("_NET_ACTIVE_WINDOW");
  size_t ncl; uint32_t *cl=client_list(&ncl); long active=prop_card(root,A_NET_ACTIVE);
  xres_init();
  printf("window\tparent\tdepth\tmap_state\toverride_redirect\tx\ty\twidth\theight\tmanaged\tactive\tpid\tclient_pid\twm_class\twm_name\tnet_wm_name\tclient_machine\twm_command\n");
  size_t cap=1024, top=0; uint32_t *stk=malloc(cap*sizeof *stk), *par=malloc(cap*sizeof *par); stk[top]=root; par[top++]=0; long count=0;
  while (top) { uint32_t w=stk[--top], pw=par[top]; count++;
    uint8_t r[16]; r[0]=3; r[1]=0; p16(r+2,2); p32(r+4,w); send_req(r,8); uint8_t *wa=reply(seq); if(!wa) continue; /* window vanished */
    r[0]=14; send_req(r,8); uint8_t *ge=reply(seq); if(!ge){ free(wa); continue; }
    uint8_t t[16]={40,0,4,0}; p32(t+4,w); p32(t+8,root); p16(t+12,0); p16(t+14,0); send_req(t,16); uint8_t *tr=reply(seq);
    int x=tr?(int16_t)g16(tr+12):0, y=tr?(int16_t)g16(tr+14):0; free(tr);
    static const char *ms[]={"Unmapped","Unviewable","Viewable"}; int managed=0; for(size_t i=0;i<ncl;i++) if(cl[i]==w) managed=1;
    printf("0x%x\t0x%x\t%d\t%s\t%d\t%d\t%d\t%u\t%u\t%s\t%s\t%ld\t%ld\t",w,pw,ge[1],wa[26]<3?ms[wa[26]]:"?",wa[27],x,y,g16(ge+16),g16(ge+18),managed?"yes":"no",(long)w==active?"yes":"no",prop_card(w,A_NET_WM_PID),w==root?-1:client_pid(w));
    put_prop_text(w,67); putchar('\t'); put_prop_text(w,39); putchar('\t'); put_prop_text(w,A_NET_WM_NAME); putchar('\t'); put_prop_text(w,36); putchar('\t'); put_prop_text(w,34); putchar('\n');
    free(wa); free(ge);
    r[0]=15; p32(r+4,w); send_req(r,8); uint8_t *qt=reply(seq); if(!qt) continue; uint16_t nc=g16(qt+16);
    for (int i=nc-1;i>=0;i--) { if(top==cap){ cap*=2; stk=realloc(stk,cap*sizeof *stk); par=realloc(par,cap*sizeof *par);} stk[top]=g32(qt+32+4*i); par[top++]=w; }
    free(qt); }
  fprintf(stderr,"c0f-x11: windows=%ld managed_clients=%zu active=0x%lx\n",count,ncl,active<0?0:active); free(cl); free(stk); free(par);
}

/* ---- clipboard ---- */
static uint32_t mywin, A_INCR, A_TARGETS, A_TIMESTAMP, want_sel, want_tgt;
static int wait_event(int code, uint32_t win, uint32_t a, uint8_t *out){ /* code 31 SelectionNotify (requestor@8), 28 PropertyNotify NewValue (window@4, atom@8) */
  for(;;){ for(int i=0;i<evn;i++){ uint8_t *b=evq[i].b; int c=b[0]&0x7f; int hit = (c==31&&code==31&&g32(b+8)==win&&g32(b+12)==want_sel&&g32(b+16)==want_tgt) || (c==28&&code==28&&g32(b+4)==win&&g32(b+8)==a&&b[16]==0);
        if(hit){ memcpy(out,b,32); memmove(&evq[i],&evq[i+1],(size_t)(evn-i-1)*sizeof(ev_t)); evn--; return 0; } }
    uint8_t h[32]; if(rd_all(h,32)) return -1; if(h[0]==1){ uint32_t len=g32(h+4); uint8_t *s=malloc((size_t)len*4+1); rd_all(s,(size_t)len*4); free(s); continue; } if(h[0]==0) continue; queue_ev(h); }
}
static uint32_t server_now(void){ /* append 0 bytes to a property on our window -> PropertyNotify carries server time */
  uint8_t r[24]={18,2,6,0}; p32(r+4,mywin); p32(r+8,9 /*CUT_BUFFER1? any predefined*/); p32(r+12,31); r[16]=8; p32(r+20,0); send_req(r,24);
  uint8_t ev[32]; if(wait_event(28,mywin,9,ev)) return 0; return g32(ev+12); }
static uint8_t *convert(uint32_t sel, uint32_t target, uint32_t *type, int *fmt, size_t *n, const char **st){
  uint32_t prop=sel; uint8_t r[24]={24,0,6,0}; p32(r+4,mywin); p32(r+8,sel); p32(r+12,target); p32(r+16,prop); p32(r+20,0); want_sel=sel; want_tgt=target; send_req(r,24);
  uint8_t ev[32]; if(wait_event(31,mywin,0,ev)){ *st="TIMEOUT"; return NULL; }
  if (g32(ev+20)==0){ *st="REFUSED_BY_OWNER"; return NULL; }
  uint8_t *v=getprop(mywin,prop,1,type,fmt,n); if(!v){ *st="GETPROPERTY_ERROR"; return NULL; }
  if (*type==A_INCR && A_INCR) { free(v); size_t cap=1<<20, tot=0; uint8_t *all=malloc(cap); int f2=8; uint32_t t2=0, tt=0;
    for(int i=0;i<evn;){ uint8_t *b=evq[i].b; if((b[0]&0x7f)==28&&g32(b+4)==mywin&&g32(b+8)==prop){ memmove(&evq[i],&evq[i+1],(size_t)(evn-i-1)*sizeof(ev_t)); evn--; } else i++; }
    for(;;){ if(wait_event(28,mywin,prop,ev)){ *st="INCR_TIMEOUT"; *n=tot; *fmt=f2; *type=tt; return all; }
      size_t k; uint8_t *c=getprop(mywin,prop,1,&t2,&f2,&k); if(!c) break; if(t2==0){ free(c); continue; } /* stale notification */
      tt=t2; if(k==0){ free(c); break; }
      if(tot+k>cap){ while(tot+k>cap) cap*=2; all=realloc(all,cap);} memcpy(all+tot,c,k); tot+=k; free(c); }
    *n=tot; *fmt=f2; *type=tt; *st="OK_INCR"; return all; }
  *st= *n?"OK":"EMPTY"; return v;
}
static void owner_info(uint32_t w, long *pid, char *cls, size_t cl){ *pid=client_pid(w); cls[0]=0; uint32_t cur=w;
  for (int depth=0; cur && cur!=root && depth<8; depth++) { long p=prop_card(cur,A_NET_WM_PID); if(p>0&&*pid<0) *pid=p;
    if(!cls[0]){ uint32_t t; int f; size_t n; uint8_t *v=getprop(cur,67,0,&t,&f,&n); if(v&&n&&f==8){ for(size_t i=0;i<n;i++) if(!v[i]) v[i]='|'; snprintf(cls,cl,"%.*s",(int)n,(char*)v);} free(v); }
    if(*pid>0&&cls[0]) return;
    long lead=prop_card(cur,A_CLIENT_LEADER); if(lead>0&&(uint32_t)lead!=cur){ cur=(uint32_t)lead; continue; }
    uint8_t r[8]={15,0,2,0}; p32(r+4,cur); send_req(r,8); uint8_t *q=reply(seq); if(!q) return; cur=g32(q+12); free(q); }
}
static void do_clipboard(const char *outdir){
  if (mkdir(outdir,0700) && errno!=EEXIST) die(2,"cannot create output directory");
  A_NET_WM_PID=atom("_NET_WM_PID"); A_INCR=atom_std("INCR"); A_TARGETS=atom_std("TARGETS"); A_TIMESTAMP=atom_std("TIMESTAMP"); A_CLIENT_LEADER=atom("WM_CLIENT_LEADER"); xres_init();
  uint32_t sels[3]={atom_std("CLIPBOARD"),1 /*PRIMARY*/,2 /*SECONDARY*/}; const char *sn[3]={"CLIPBOARD","PRIMARY","SECONDARY"};
  mywin=idbase|(1&idmask); uint8_t cw[36]={1,0,9,0}; p32(cw+4,mywin); p32(cw+8,root); p16(cw+12,0); p16(cw+14,0); p16(cw+16,1); p16(cw+18,1); p16(cw+20,0); p16(cw+22,2 /*InputOnly*/); p32(cw+24,0); p32(cw+28,0x800 /*event-mask*/); p32(cw+32,0x400000 /*PropertyChange*/);
  send_req(cw,36); sync_x(); if(last_err && last_err_seq==(uint16_t)(seq-1)) die(4,"cannot create helper window");
  uint32_t now=server_now(); struct timespec wall; clock_gettime(CLOCK_REALTIME,&wall);
  fprintf(stderr,"c0f-x11: server_time_ms=%u (X server uptime clock; acquired_server_ms later than this = owner sent an invalid TIMESTAMP)\n",now);
  printf("selection\towner_window\towner_pid\towner_class\tacquired_server_ms\tacquired_utc_estimate\ttarget\treturned_type\tformat\tbytes\tsha256\tfile\tstatus\n");
  for (int s=0;s<3;s++) {
    if (!sels[s]) { printf("%s\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\tNO_SUCH_ATOM\n",sn[s]); continue; }
    uint8_t r[8]={23,0,2,0}; p32(r+4,sels[s]); send_req(r,8); uint8_t *rp=reply(seq); uint32_t own=rp?g32(rp+8):0; free(rp);
    if (!own) { printf("%s\t-\t-\t-\t-\t-\t-\t-\t-\t0\t-\t-\tNO_OWNER (empty)\n",sn[s]); continue; }
    long pid; char cls[256]; owner_info(own,&pid,cls,sizeof cls);
    char acq[64]="-"; long long acq_ms=-1; uint32_t ty; int fm; size_t n; const char *st;
    uint8_t *tv=A_TIMESTAMP?convert(sels[s],A_TIMESTAMP,&ty,&fm,&n,&st):NULL;
    if (tv && n>=4 && now) { uint32_t ts=g32(tv); acq_ms=ts; if (ts && (uint32_t)(now-ts)<0x80000000u) { long long ago=(long long)(uint32_t)(now-ts); fmt_utc(acq,sizeof acq,(int64_t)wall.tv_sec-(ago/1000),-1); } }
    free(tv);
    uint8_t *tl=A_TARGETS?convert(sels[s],A_TARGETS,&ty,&fm,&n,&st):NULL;
    size_t nt; uint32_t *tg;
    if (!tl || fm!=32) { printf("%s\t0x%x\t%ld\t",sn[s],own,pid); tsv_str(stdout,cls[0]?cls:"-"); printf("\t%lld\t%s\tTARGETS\t-\t-\t0\t-\t-\t%s (falling back to UTF8_STRING/STRING)\n",acq_ms,acq,tl?"BAD_TARGETS_FORMAT":st); free(tl);
      tg=malloc(8); nt=0; uint32_t u=atom_std("UTF8_STRING"); if(u) tg[nt++]=u; tg[nt++]=31; }
    else { nt=n/4; tg=malloc(nt*4+4); for(size_t i=0;i<nt;i++) tg[i]=g32(tl+4*i); free(tl); }
    for (size_t i=0;i<nt;i++) { char *nm=atom_name(tg[i]);
      static const char *meta[]={"TARGETS","MULTIPLE","TIMESTAMP","SAVE_TARGETS","DELETE","INSERT_SELECTION","INSERT_PROPERTY","_GTK_","CLIPBOARD_MANAGER",NULL};
      int skip=0; for(int k=0;meta[k];k++) if(!strncmp(nm,meta[k],strlen(meta[k]))) skip=1;
      printf("%s\t0x%x\t%ld\t",sn[s],own,pid); tsv_str(stdout,cls[0]?cls:"-"); printf("\t%lld\t%s\t",acq_ms,acq); tsv_str(stdout,nm);
      if (skip) { printf("\t-\t-\t-\t-\t-\tLISTED_ONLY (protocol target)\n"); free(nm); continue; }
      uint8_t *v=convert(sels[s],tg[i],&ty,&fm,&n,&st);
      if (!v) { printf("\t-\t-\t0\t-\t-\t%s\n",st); free(nm); continue; }
      char safe[96]; size_t k=0; for(const char *c=nm;*c&&k<80;c++) safe[k++]=(isalnum((unsigned char)*c)||*c=='.'||*c=='-'||*c=='_')?*c:'_'; safe[k]=0;
      char fn[PATH_MAX]; snprintf(fn,sizeof fn,"%s/%s_%02zu_%s.bin",outdir,sn[s],i,safe); int fd=open(fn,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);
      if (fd>=0) { if(write(fd,v,n)!=(ssize_t)n) st="WRITE_ERROR"; close(fd); } else st="CANNOT_CREATE_FILE";
      uint8_t d[32]; char hx[65]; sha256_ctx h; sha256_init(&h); sha256_update(&h,v,n); sha256_final(&h,d); hex_encode(d,32,hx);
      char *tn=ty?atom_name(ty):strdup("None"); putchar('\t'); tsv_str(stdout,tn); printf("\t%d\t%zu\t%s\t",fm,n,hx); tsv_str(stdout,strrchr(fn,'/')+1); printf("\t%s\n",st);
      free(tn); free(v); free(nm); fflush(stdout); }
    free(tg); }
  uint8_t dw[8]={4,0,2,0}; p32(dw+4,mywin); send_req(dw,8); sync_x();
  if (interned) fprintf(stderr,"c0f-x11: note: %d standard selection atom(s) did not exist and were created\n",interned);
}

/* ---- screenshot -> PNG (stored deflate, no zlib needed) ---- */
static uint32_t crctab[256];
static void crc_init(void){ for(uint32_t n=0;n<256;n++){ uint32_t c=n; for(int k=0;k<8;k++) c= (c&1)?0xedb88320u^(c>>1):c>>1; crctab[n]=c; } }
static uint32_t crc_upd(uint32_t c, const uint8_t *b, size_t n){ for(size_t i=0;i<n;i++) c=crctab[(c^b[i])&0xff]^(c>>8); return c; }
static FILE *png; static uint32_t adl_a=1, adl_b=0; static size_t raw_total, raw_done; static uint8_t blk[65535]; static size_t blkn;
static void chunk(const char *type, const uint8_t *d, uint32_t n){ uint8_t h[8]={n>>24,n>>16,n>>8,n,type[0],type[1],type[2],type[3]}; fwrite(h,1,8,png); if(n) fwrite(d,1,n,png);
  uint32_t c=crc_upd(0xffffffffu,h+4,4); c=crc_upd(c,d,n)^0xffffffffu; uint8_t t[4]={c>>24,c>>16,c>>8,c}; fwrite(t,1,4,png); }
static void flush_blk(void){ uint8_t *o=malloc(blkn+5); int final = raw_done==raw_total; o[0]=final?1:0; o[1]=blkn; o[2]=blkn>>8; o[3]=~blkn; o[4]=(~blkn)>>8; memcpy(o+5,blk,blkn); chunk("IDAT",o,(uint32_t)(blkn+5)); free(o); blkn=0; }
static void raw_put(const uint8_t *d, size_t n){ for(size_t i=0;i<n;i++){ adl_a=(adl_a+d[i])%65521; adl_b=(adl_b+adl_a)%65521; }
  while(n){ size_t k=sizeof blk-blkn; if(k>n) k=n; memcpy(blk+blkn,d,k); blkn+=k; d+=k; n-=k; raw_done+=k; if(blkn==sizeof blk||raw_done==raw_total) flush_blk(); } }
static int shift_of(uint32_t m){ int s=0; if(!m) return 0; while(!(m&1)){ m>>=1; s++; } return s; }
static int bits_of(uint32_t m){ int b=0; while(m){ b+=m&1; m>>=1;} return b; }
static void do_screenshot(const char *out){
  if (bpp!=32 && bpp!=24 && bpp!=16) die(5,"unsupported pixel format (only TrueColor 16/24/32 bpp)");
  png=fopen(out,"wbx"); if(!png) die(2,"cannot create output file"); crc_init();
  static const uint8_t sig[8]={0x89,'P','N','G',13,10,26,10}; fwrite(sig,1,8,png);
  uint8_t ih[13]; memset(ih,0,sizeof ih); ih[0]=0; ih[1]=0; ih[2]=sw>>8; ih[3]=sw; ih[4]=0; ih[5]=0; ih[6]=sh>>8; ih[7]=sh; ih[8]=8; ih[9]=2; ih[10]=0; ih[11]=0; ih[12]=0; chunk("IHDR",ih,13);
  uint8_t zh[2]={0x78,0x01}; chunk("IDAT",zh,2);
  raw_total=(size_t)sh*(1+3*(size_t)sw); raw_done=0;
  int Bpp=bpp/8; size_t stride=((size_t)sw*bpp+scanpad-1)/scanpad*scanpad/8; int rows=(int)(4*1024*1024/stride); if(rows<1) rows=1;
  int rs=shift_of(rmask), gs=shift_of(gmask), bs=shift_of(bmask), rb=bits_of(rmask), gb=bits_of(gmask), bb=bits_of(bmask);
  uint8_t *line=malloc(1+3*(size_t)sw);
  for (int y0=0;y0<sh;y0+=rows) { int h=(y0+rows>sh)?sh-y0:rows;
    uint8_t r[20]={73,2,5,0}; p32(r+4,root); p16(r+8,0); p16(r+10,(uint16_t)y0); p16(r+12,sw); p16(r+14,(uint16_t)h); p32(r+16,0xffffffffu); send_req(r,20);
    uint8_t *rp=reply(seq); if(!rp) { fclose(png); unlink(out); die(4,"GetImage failed"); }
    for (int yy=0;yy<h;yy++) { const uint8_t *src=rp+32+(size_t)yy*stride; line[0]=0;
      for (int x=0;x<sw;x++) { const uint8_t *px=src+(size_t)x*Bpp; uint32_t v;
        if (Bpp==4) v= img_lsb? g32(px) : ((uint32_t)px[0]<<24|(uint32_t)px[1]<<16|(uint32_t)px[2]<<8|px[3]);
        else if (Bpp==3) v= img_lsb? (px[0]|px[1]<<8|(uint32_t)px[2]<<16) : ((uint32_t)px[0]<<16|px[1]<<8|px[2]);
        else v= img_lsb? g16(px) : (uint32_t)(px[0]<<8|px[1]);
        uint32_t R=(v&rmask)>>rs, G=(v&gmask)>>gs, B=(v&bmask)>>bs;
        line[1+3*x]= rb>=8? R>>(rb-8) : (uint8_t)(R*255/((1u<<rb)-1)); line[2+3*x]= gb>=8? G>>(gb-8) : (uint8_t)(G*255/((1u<<gb)-1)); line[3+3*x]= bb>=8? B>>(bb-8) : (uint8_t)(B*255/((1u<<bb)-1)); }
      raw_put(line,1+3*(size_t)sw); }
    free(rp); }
  uint32_t ad=(adl_b<<16)|adl_a; uint8_t at[4]={ad>>24,ad>>16,ad>>8,ad}; chunk("IDAT",at,4); chunk("IEND",NULL,0);
  if (fclose(png)) die(2,"write error"); free(line);
  fprintf(stderr,"c0f-x11: screenshot %ux%u depth %d bpp %d -> %s\n",sw,sh,root_depth,bpp,out);
}

int main(int argc, char **argv){
  const char *disp=getenv("DISPLAY"), *auth=getenv("XAUTHORITY"), *rp=NULL; int c;
  while((c=getopt(argc,argv,"d:a:r:t:V"))!=-1) switch(c){ case 'd':disp=optarg;break; case 'a':auth=optarg;break; case 'r':rp=optarg;break; case 't':tmo=atoi(optarg)*1000;break;
    case 'V': printf("c0f-x11 %s (C0F helper)\n",C0F_HELPER_VERSION); return 0; default: return 2; }
  if (optind>=argc || !disp) { fprintf(stderr,"usage: c0f-x11 [-d DISPLAY] [-a XAUTHORITY] [-r ROOTPREFIX] [-t SEC] info|windows|clipboard OUTDIR|screenshot OUT.png\n"); return 2; }
  const char *cmd=argv[optind]; signal(SIGPIPE,SIG_IGN);
  xconnect(disp,auth,rp);
  if (!strcmp(cmd,"info")) { printf("display\t%s\nvendor\t%s\nrelease\t%u\nroot\t0x%x\nwidth\t%u\nheight\t%u\ndepth\t%d\nbits_per_pixel\t%d\nimage_byte_order\t%s\nmasks\t%06x/%06x/%06x\n",disp,vendor,release,root,sw,sh,root_depth,bpp,img_lsb?"LSBFirst":"MSBFirst",rmask,gmask,bmask); return 0; }
  if (!strcmp(cmd,"windows")) { do_windows(); return 0; }
  if (!strcmp(cmd,"clipboard") && optind+1<argc) { do_clipboard(argv[optind+1]); return 0; }
  if (!strcmp(cmd,"screenshot") && optind+1<argc) { do_screenshot(argv[optind+1]); return 0; }
  fprintf(stderr,"c0f-x11: unknown command\n"); return 2;
}
