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
