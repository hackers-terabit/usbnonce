#!/bin/bash
#Assuming killall is installed,not checking since this is meant to be just an example script
#these won't work if priviledge isn't root :(
killall -s SIGSTOP agetty
killall -s SIGSTOP login
#this following maybe too much,might have you do hard reset if things go sideways,
#meh,why not :)
killall -s SIGSTOP bash  
killall -s SIGSTOP X


##maybe in the future...
#cryptsetup luksClose somedisk
#shred -fuz /tmp/*
#/usr/local/bin/mybackupscript.sh
#ansible-playbook .... #build some VMs
#etc... whatever you want goes here :)

