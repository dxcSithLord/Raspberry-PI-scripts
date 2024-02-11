# Raspberry-PI-scripts
The is a placeholder for general scripts and files that are used in Raspberry Pi OS

~~LXDE-pi_panel - See https://thepihut.com/blogs/raspberry-pi-tutorials/how-to-lock-your-raspberry-pi-screen for description.~~
There was a small issue with LightGDM - Use Ctrl-Alt-F7 and Ctrl-Alt-F8 to switch between lock screen and X Windows session.

Alternative is to use Wayland, which can be enabled via raspi-conf:

sudo raspi-conf
From the top level menu, select 
**advanced Options**

From the Advanced Options menu, select 
**A6 Wayland  Switch between X and Wayland support**
save changes and exit raspi-conf
(Reboot required)

sudo apt install swaylock

From the menu, select Preferences -> Main Menu Editor

Select "New Item"

Name: Lock...
Command: /usr/bin/swaylock -lk
Comment: lock screen

OK to save new menu item

OK to close Main Menu editor

Lock option should be available in menu under Preferences and if you can't find it there, look under "Other"

The lock screen is blank white (you can change this colour).
Type password to unlock

