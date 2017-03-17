
** This is a fork of slock http://tools.suckless.org/slock 
I have significantly modified slock.c,config.h and this README.
My modfiications include compatibility with USBNONCE,text messages on the lock screen
as well as continuous operation. **

#slock - simple screen locker

simple screen locker utility for X.


##Requirements

In order to build slock you need the Xlib header files.


##Installation

Edit config.mk to match your local setup (slock is installed into
the /usr/local namespace by default).

Afterwards enter the following command to build and install slock
(if necessary as root):

    make clean install


##Running slock

Simply invoke the 'slock' command. To get out of it, enter your password.
