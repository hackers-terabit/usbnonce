/* user and group to drop privileges to */
static const char *user  = "nobody";
static const char *group = "nogroup";

static const char *colorname[NUMCOLS] = {
	[INIT] =   "darkblue",     /* after initialization */
	[INPUT] =  "blue",   /* during input */
	[FAILED] = "red",   /* wrong password */
	[USBWAIT] = "green",
	[USBFAIL] = "yellow"
};

/* treat a cleared input like a wrong password (color) */
static const int failonclear = 1;

/* message font */
static const char *msgfont= "lucidasanstypewriter-bold-24";

/* IP address to liste on for USB nonce messages */
static const char *usnip="127.0.0.1";

/* Port */

static uint16_t usnport=56789;
