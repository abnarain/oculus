Oculus:
===============
Lightweight tool to collect wireless traces information from laptop
Does capture on a single channel on a monitor inteface provided to it.

Create a monitor mode interface by using the following command :
sudo iw phy phy0 interface add phy0 type monitor flags fcsfail control otherbss 

Turn it up :
sudo ifconfig phy0 up

To use:
sudo ./oculus -i phy0
