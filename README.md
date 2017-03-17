# USBNONCE

## *While this application works as expected in testing,please test it on your system well before using it for anything serious.*

 This small C program is meant to enable the usage of
 removable storage drives as a factor of authentication.

 *TL;DR: it places random bytes on a usb drive,sends UDP event notification when the drive is plugged in and the bytes are verified (or fail verification).*
 *it will also run specified commands when the synced usb is removed and when it's plugged in again*
 *Check out uslock as well, a slock fork that works with usbnonce*
 	
 At start-up it will await for a new drive to be plugged in.
 When a new drive with a usable partition and a file system matching
 the default of ext4 (or user specfied via -f flag) is detected,
	it will place bytes generated by the system's random number generator 
 in a file called '.nonce' at the root of the first detected
 partition and file system on the drive.

 At this point,it is "synced" awaiting the removal of the drive.
 
 When the drive is removed it becomes 'active' and notifies 
 anyone listening to 'LOCK',when the removable drive is re-inserted,
 it should check for the '.nonce' bytes to see if they match the bytes
 stored when it became 'synced'. if they match a notification to unlock
 is sent and a new 'sync' is attempted.

 The goal is simply to notify any listeners that a removable drive 
 with the unique and random nonce(use once) bytes has been synchronized,removed/active and
 when a new drive is inserted to tell the same listeners if a valid nonce was found.

 I wanted to do things like lock screens(on a VM host and all it's guests),
 close particular encryted disks,suspend or kill processes and stop/start services
 when the USB drive in my possession is physhically plugged into the system/network.

If you plan on using this, be aware of some security considerations:

* this isn't meant to be your first or last line of defense when it comes to
  authentication or any form of security.
		
* It is simply a very cheap means of using 'posession' of a removable drive
  to make decisions and take actions. 
* It is assumed(**VERY IMPORTANT**) that everyone that is able to send traffic to the 
  'multi cast'(or set via -d) IP address and port is trusted otherwise they can tell all listeners
  to lock or unlock at will which makes this whole thing pointless 
  (when in doubt use 127.0.0.1 which is the default and drop the udp port on ingress points to the trusted network)
		
* If you can't ensure physhical posession of the drive by you and only you after this application is 'active'
  it is of no use to you.
		
* Lastly, udev notifications aren't all that reliable,so plugging in/out a few times might be needed.

* There are example lock/unlock scripts(cmdlock.sh and cmdunlock.sh),if you decide to use them and enable suspension of all bash processes and X,
  Then be sure to start usbnonce from your init script,if you start it from a bash shell,suspending all bash processes will suspend usbnonce too,
  leaving you the only option of a hard reset of the system. 
  
As an example client,The uslock/ directory contains a heavily modified slock(http://tools.suckless.org/slock ) that can be used with usbnonce.
Simply run both applications,insert a usb,when removed it should lock the screen. It will require the same removable 
drive to be re-inserted before you can type in your credentials for unlocking the screen. 

# Usage


```		
USBnonce 0.1a Usage:

	usbnonce [-mfdph]
	-m <mountpoint>	 set the filesystem mount point that will be used to temporarily mount the removable drive.
	-f <filesystem>	 set the filesystem the removable drive is expected to use.
	-d <ipv4addr>	 set the destination IPv4 address for UDP notifications
	-p <port>	 set the destination port number for UDP notifications.
	-h 	 Display this usage info.
```

# BUGS


* When  a qemu VM is in full screen,it won't lock as a result of a USBNONCE LOCK event message.

Will add more here as I find them.
