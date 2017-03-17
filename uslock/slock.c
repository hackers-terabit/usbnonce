/* See LICENSE file for license details. */
#define _XOPEN_SOURCE 500
#if HAVE_SHADOW_H
#include <shadow.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <linux/in.h>

#include <X11/extensions/Xrandr.h>
#include <X11/keysym.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>



#include "arg.h"
#include "util.h"

char *argv0;
char message[64];
int fails;

enum {
	INIT,
	INPUT,
	FAILED,
	USBWAIT,
	USBFAIL,
	NUMCOLS
};

struct lock {
	int screen;
	Window root, win;
	Pixmap pmap;
	Display *dpy;
	unsigned long colors[NUMCOLS];
};

struct xrandr {
	int active;
	int evbase;
	int errbase;
};

#include "config.h"

static void
die(const char *errstr, ...)
{
	va_list ap;

	va_start(ap, errstr);
	vfprintf(stderr, errstr, ap);
	va_end(ap);
	exit(1);
}

#ifdef __linux__
#include <fcntl.h>
#include <linux/oom.h>

static void
dontkillme(void)
{
	FILE *f;
	const char oomfile[] = "/proc/self/oom_score_adj";

	if (!(f = fopen(oomfile, "w"))) {
		if (errno == ENOENT)
			return;
		die("slock: fopen %s: %s\n", oomfile, strerror(errno));
	}
	fprintf(f, "%d", OOM_SCORE_ADJ_MIN);
	if (fclose(f)) {
		if (errno == EACCES)
			die("slock: unable to disable OOM killer. "
			    "Make sure to suid or sgid slock.\n");
		else
			die("slock: fclose %s: %s\n", oomfile, strerror(errno));
	}
}
#endif

static const char *
gethash(void)
{
	const char *hash;
	struct passwd *pw;

	/* Check if the current user has a password entry */
	errno = 0;
	if (!(pw = getpwuid(getuid()))) {
		if (errno)
			die("slock: getpwuid: %s\n", strerror(errno));
		else
			die("slock: cannot retrieve password entry\n");
	}
	hash = pw->pw_passwd;

#if HAVE_SHADOW_H
	if (!strcmp(hash, "x")) {
		struct spwd *sp;
		if (!(sp = getspnam(pw->pw_name)))
			die("slock: getspnam: cannot retrieve shadow entry. "
			    "Make sure to suid or sgid slock.\n");
		hash = sp->sp_pwdp;
	}
#else
	if (!strcmp(hash, "*")) {
#ifdef __OpenBSD__
		if (!(pw = getpwuid_shadow(getuid())))
			die("slock: getpwnam_shadow: cannot retrieve shadow entry. "
			    "Make sure to suid or sgid slock.\n");
		hash = pw->pw_passwd;
#else
		die("slock: getpwuid: cannot retrieve shadow entry. "
		    "Make sure to suid or sgid slock.\n");
#endif /* __OpenBSD__ */
	}
#endif /* HAVE_SHADOW_H */

	return hash;
}

static void
readpw(Display *dpy, struct xrandr *rr, struct lock **locks, int nscreens,
       const char *hash)
{
	XRRScreenChangeNotifyEvent *rre;
	char buf[32], passwd[256], *inputhash;
	int num, screen, running, failure, oldc;
	unsigned int len, color;
	KeySym ksym;
	XEvent ev;
	XWindowAttributes xa;
	
	len = 0;
	running = 1;
	failure = 0;
	oldc = INIT;
	XGetWindowAttributes(dpy,DefaultRootWindow(dpy),&xa);

	snprintf(message,64,"USB NONCE IS VERIFIED. ENTER YOUR LOGIN PASSWORD TO UNLOCK.");
	XFlush(dpy);
	while (running && !XNextEvent(dpy, &ev)) {
		for (screen = 0; screen < nscreens; screen++) {
			XDrawString(locks[screen]->dpy,locks[screen]->win,DefaultGC(dpy,screen),(xa.width/2)-((strlen(message)*24)/2),(xa.height/2)-24,message,strlen(message));
		}
		if (ev.type == KeyPress) {
			explicit_bzero(&buf, sizeof(buf));
			num = XLookupString(&ev.xkey, buf, sizeof(buf), &ksym, 0);
			if (IsKeypadKey(ksym)) {
				if (ksym == XK_KP_Enter)
					ksym = XK_Return;
				else if (ksym >= XK_KP_0 && ksym <= XK_KP_9)
					ksym = (ksym - XK_KP_0) + XK_0;
			}
			if (IsFunctionKey(ksym) ||
			    IsKeypadKey(ksym) ||
			    IsMiscFunctionKey(ksym) ||
			    IsPFKey(ksym) ||
			    IsPrivateKeypadKey(ksym))
				continue;
			switch (ksym) {
			case XK_Return:
				passwd[len] = '\0';
				errno = 0;
				if (!(inputhash = crypt(passwd, hash)))
					fprintf(stderr, "slock: crypt: %s\n", strerror(errno));
				else
					running = !!strcmp(inputhash, hash);
				if (running) {
					XBell(dpy, 100);
					failure = 1;
					++fails;
				}
				explicit_bzero(&passwd, sizeof(passwd));
				len = 0;
				break;
			case XK_Escape:
				explicit_bzero(&passwd, sizeof(passwd));
				len = 0;
				break;
			case XK_BackSpace:
				if (len)
					passwd[len--] = '\0';
				break;
			default:
				if (num && !iscntrl((int)buf[0]) &&
				    (len + num < sizeof(passwd))) {
					memcpy(passwd + len, buf, num);
					len += num;
				}
				break;
			}
			color = len ? INPUT : ((failure || failonclear) ? FAILED : INIT);
			if (running && oldc != color) {
				for (screen = 0; screen < nscreens; screen++) {
					XSetWindowBackground(dpy,
					                     locks[screen]->win,
					                     locks[screen]->colors[color]);
					XClearWindow(dpy, locks[screen]->win);
					if(color==FAILED)
						snprintf(message,64,"BAD LOGIN PASSWORD. TRY AGAIN [ %i TRIES]",fails);
					XDrawString(locks[screen]->dpy,locks[screen]->win,DefaultGC(dpy,screen),(xa.width/2)-((strlen(message)*24)/2),(xa.height/2)-24,message,strlen(message));
					
				}
				oldc = color;
			}
		} else if (rr->active && ev.type == rr->evbase + RRScreenChangeNotify) {
			rre = (XRRScreenChangeNotifyEvent*)&ev;
			for (screen = 0; screen < nscreens; screen++) {
				if (locks[screen]->win == rre->window) {
					if (rre->rotation == RR_Rotate_90 ||
					    rre->rotation == RR_Rotate_270)
						XResizeWindow(dpy, locks[screen]->win,
						              rre->height, rre->width);
					else
						XResizeWindow(dpy, locks[screen]->win,
						              rre->width, rre->height);
					XClearWindow(dpy, locks[screen]->win);
					break;
				}
			 
			}
		} else {
			for (screen = 0; screen < nscreens; screen++)
				XRaiseWindow(dpy, locks[screen]->win);
				
		}
	}
}

static struct lock *
lockscreen(Display *dpy, struct xrandr *rr, int screen)
{
	char curs[] = {0, 0, 0, 0, 0, 0, 0, 0};
	int i, ptgrab, kbgrab;
	struct lock *lock;
	XColor color, dummy;
	XSetWindowAttributes wa;
	Cursor invisible;

	if (dpy == NULL || screen < 0 || !(lock = malloc(sizeof(struct lock))))
		return NULL;

	lock->screen = screen;
	lock->root = RootWindow(dpy, lock->screen);

	for (i = 0; i < NUMCOLS; i++) {
		XAllocNamedColor(dpy, DefaultColormap(dpy, lock->screen),
		                 colorname[i], &color, &dummy);
		lock->colors[i] = color.pixel;
	}

	/* init */
	wa.override_redirect = 1;
	wa.background_pixel = lock->colors[INIT];
	lock->win = XCreateWindow(dpy, lock->root, 0, 0,
	                          DisplayWidth(dpy, lock->screen),
	                          DisplayHeight(dpy, lock->screen),
	                          0, DefaultDepth(dpy, lock->screen),
	                          CopyFromParent,
	                          DefaultVisual(dpy, lock->screen),
	                          CWOverrideRedirect | CWBackPixel, &wa);
	lock->pmap = XCreateBitmapFromData(dpy, lock->win, curs, 8, 8);
	invisible = XCreatePixmapCursor(dpy, lock->pmap, lock->pmap,
	                                &color, &color, 0, 0);
	XDefineCursor(dpy, lock->win, invisible);
	/* set window color to USBWAIT */
	XSetWindowBackground(dpy,
	                     lock->win,
	                     lock->colors[USBWAIT]);
	XClearWindow(dpy, lock->win);
	XFlush(dpy);
	/* Try to grab mouse pointer *and* keyboard for 600ms, else fail the lock */
	for (i = 0, ptgrab = kbgrab = -1; i < 6; i++) {
		if (ptgrab != GrabSuccess) {
			ptgrab = XGrabPointer(dpy, lock->root, False,
			                      ButtonPressMask | ButtonReleaseMask |
			                      PointerMotionMask, GrabModeAsync,
			                      GrabModeAsync, None, invisible, CurrentTime);
		}
		if (kbgrab != GrabSuccess) {
			kbgrab = XGrabKeyboard(dpy, lock->root, True,
			                       GrabModeAsync, GrabModeAsync, CurrentTime);
		}

		/* input is grabbed: we can lock the screen */
		if (ptgrab == GrabSuccess && kbgrab == GrabSuccess) {
			XMapRaised(dpy, lock->win);
			if (rr->active)
				XRRSelectInput(dpy, lock->win, RRScreenChangeNotifyMask);

			XSelectInput(dpy, lock->root, SubstructureNotifyMask);
			return lock;
		}

		/* retry on AlreadyGrabbed but fail on other errors */
		if ((ptgrab != AlreadyGrabbed && ptgrab != GrabSuccess) ||
		    (kbgrab != AlreadyGrabbed && kbgrab != GrabSuccess))
			break;

		usleep(100000);
	}

	/* we couldn't grab all input: fail out */
	if (ptgrab != GrabSuccess)
		fprintf(stderr, "slock: unable to grab mouse pointer for screen %d\n",
		        screen);
	if (kbgrab != GrabSuccess)
		fprintf(stderr, "slock: unable to grab keyboard for screen %d\n",
		        screen);
	
			
		        
	return NULL;
}
struct usnudp{
	struct sockaddr_in srv,clnt;
	struct lock **locks;
	int sk;
	int nscreens;
};

static void usbnonce_init(struct usnudp *usu){
		
	memset(usu,0,sizeof(struct usnudp));
	memset(&usu->srv,0,sizeof(struct sockaddr_in));
	memset(&usu->clnt,0,sizeof(struct sockaddr_in));
	
	usu->sk=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
	if(usu->sk==-1){
		perror("Socket error");
		exit(1);
	}

	
	usu->srv.sin_family=AF_INET;
	htonl(inet_aton(usnip,&usu->srv.sin_addr));
	usu->srv.sin_port=htons(usnport);
	
	if(bind(usu->sk,(struct sockaddr *)&usu->srv,sizeof(usu->srv))==-1){
		perror("Bind error");
		exit(1);
	}
}
inline int usbnonce(struct usnudp *usu){
	
	int ret;
	socklen_t clen=sizeof(usu->clnt);
	char buf[32];

	
	
	memset(&buf,0,32);
	

	printf("Awaiting USBnonce notification...\n");
	fflush(stdout);
	while(1){
		
		ret=recvfrom(usu->sk,buf,32,0,(struct sockaddr *) &usu->clnt,&clen);
		if(ret<1){
			perror("recvfrom error");
			return -1;
		}else{
			printf("USN debug:%s\n",buf);
		}
		if(strncmp(buf,"LOCK",4)==0){
			return 1;
		}else if(strncmp(buf,"UNLOCKREADY",11)==0){
			return 0;
		}else if(strncmp(buf,"FAILUNLOCK",10)==0){
			return -1;
		}
	}	
}



static void
usage(void)
{
	die("usage: slock [-v] [cmd [arg ...]]\n");
}

int
main(int argc, char **argv) {
	struct xrandr rr;
	struct lock **locks;
	struct passwd *pwd;
	struct group *grp;
	struct usnudp usu;
	uid_t duid;
	gid_t dgid;
	const char *hash;
	Display *dpy;
	Font fnt;
	XWindowAttributes xa;
	int s, nlocks, nscreens,usblock=0,screen,child,status;
	fails=-1;
	
	ARGBEGIN {
	case 'v':
		fprintf(stderr, "slock-"VERSION"\n");
		return 0;
	default:
		usage();
	} ARGEND
	
	/* Setup udp socketish things */
	usbnonce_init(&usu);
	
	/* validate drop-user and -group */
	errno = 0;
	if (!(pwd = getpwnam(user)))
		die("slock: getpwnam %s: %s\n", user,
		    errno ? strerror(errno) : "user entry not found");
	duid = pwd->pw_uid;
	errno = 0;
	if (!(grp = getgrnam(group)))
		die("slock: getgrnam %s: %s\n", group,
		    errno ? strerror(errno) : "group entry not found");
	dgid = grp->gr_gid;

#ifdef __linux__
	dontkillme();
#endif

	hash = gethash();
	errno = 0;
	if (!crypt("", hash))
		die("slock: crypt: %s\n", strerror(errno));
	while(1){
		
		child=fork();
		
		if(!child){
			if (!(dpy = XOpenDisplay(NULL)))
				die("slock: cannot open display\n");
				
			XGetWindowAttributes(dpy,DefaultRootWindow(dpy),&xa);
			
			fnt=XLoadFont(dpy,msgfont);
			XSetFont(dpy,DefaultGC(dpy,screen),fnt);
			
			/* drop privileges */
			if (setgroups(0, NULL) < 0)
				die("slock: setgroups: %s\n", strerror(errno));
			if (setgid(dgid) < 0)
				die("slock: setgid: %s\n", strerror(errno));
			if (setuid(duid) < 0)
				die("slock: setuid: %s\n", strerror(errno));
		
					
			/* check for Xrandr support */
			rr.active = XRRQueryExtension(dpy, &rr.evbase, &rr.errbase);
		
			/* get number of screens in display "dpy" and blank them */
		
			nscreens = ScreenCount(dpy);
			while(usblock<1){	
				
				/* listen for notifications,if we get anything outside of LOCK,keep looping */
				usblock=usbnonce(&usu);
				if(usblock<1)
					continue;

			if (!(locks = calloc(nscreens, sizeof(struct lock *))))
				die("slock: out of memory\n");
			
				for (nlocks = 0, s = 0; s < nscreens; s++) {
					if ((locks[s] = lockscreen(dpy, &rr, s)) != NULL)
						nlocks++;
					else
						break;
				}
			
			XSync(dpy, 0);
			
			
			/* did we manage to lock everything? */
			if (nlocks != nscreens)
				return 1;
				
			}
			
			/* run post-lock command */
			if (argc > 0) {
				switch (fork()) {
				case -1:
					die("slock: fork failed: %s\n", strerror(errno));
				case 0:
					if (close(ConnectionNumber(dpy)) < 0)
						die("slock: close: %s\n", strerror(errno));
					execvp(argv[0], argv);
					fprintf(stderr, "slock: execvp %s: %s\n", argv[0], strerror(errno));
					_exit(1);
				}
			}
			for (screen = 0; screen < nscreens; screen++) {
				locks[screen]->dpy=dpy;
			}
			usu.locks=locks;
			usu.nscreens=nscreens;
			snprintf(message,64,"INSERT REMOVABLE DRIVE");
			printf("Screen should be locked now,something went wrong if you're still seeing this before unlock.\n");
			/* everything is now blank. Wait for the correct password */
			
			for (screen = 0; screen < nscreens; screen++) {
				XDrawString(locks[screen]->dpy,locks[screen]->win,DefaultGC(dpy,screen),(xa.width/2)-((strlen(message)*24)/2),(xa.height/2)-24,message,strlen(message)); 
				XFlush(locks[screen]->dpy);

			}
		
			while(usblock){
				
				usblock=usbnonce(&usu);
				
				if(!usblock){
					readpw(dpy, &rr, locks, nscreens, hash);
				}
				else if(usblock==-1){
					printf("USB nonce token failed to verify!!\n");
					
					for (screen = 0; screen < nscreens; screen++) {
							XSetWindowBackground(dpy,
												locks[screen]->win,
												locks[screen]->colors[USBFAIL]);
							XClearWindow(dpy, locks[screen]->win);
							XSync(dpy, 0);
							usleep(1000);	
						}
				}	
			}
			
			free(locks);
			exit(0);
			
		}else{
			wait(&status);
		}
	}
	
	return 0;
}
