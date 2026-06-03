.PHONY : tc ts uc us tls-block clean install uninstall android-install android-uninstall

all: tc ts uc us tls-block

tc:
	cd tc; make; cd ..

ts:
	cd ts; make; cd ..

uc:
	cd uc; make; cd ..

us:
	cd us; make; cd ..

tls-block:
	g++ -o bin/tls-block tls_block.cpp -lpcap

clean:
	cd tc; make clean; cd ..
	cd ts; make clean; cd ..
	cd uc; make clean; cd ..
	cd us; make clean; cd ..
	rm -f bin/tls-block
install:
	sudo cp bin/tc /usr/local/sbin
	sudo cp bin/ts /usr/local/sbin
	sudo cp bin/uc /usr/local/sbin
	sudo cp bin/us /usr/local/sbin
	sudo cp bin/tls-block /usr/local/sbin

uninstall:
	sudo rm /usr/local/sbin/tc /usr/local/sbin/ts /usr/local/sbin/uc /usr/local/sbin/us /usr/local/sbin/tls-block

android-install:
	adb push bin/tc bin/ts bin/uc bin/us bin/tls-block /data/local/tmp
	adb exec-out "su -c 'mount -o rw,remount /'"
	adb exec-out "su -c 'mkdir -p /system/xbin'"
	adb exec-out "su -c 'cp /data/local/tmp/tc /data/local/tmp/ts /data/local/tmp/uc /data/local/tmp/us /data/local/tmp/tls-block /system/xbin'"
	adb exec-out "su -c 'chmod 755 /system/xbin/tc'"
	adb exec-out "su -c 'chmod 755 /system/xbin/ts'"
	adb exec-out "su -c 'chmod 755 /system/xbin/uc'"
	adb exec-out "su -c 'chmod 755 /system/xbin/us'"
	adb exec-out "su -c 'chmod 755 /system/xbin/tls-block'"
	adb exec-out "su -c 'mount -o ro,remount /'"
	adb exec-out "su -c 'rm /data/local/tmp/tc /data/local/tmp/ts /data/local/tmp/uc /data/local/tmp/us /data/local/tmp/tls-block'"

android-uninstall:
	adb exec-out "su -c 'mount -o rw,remount /'"
	adb exec-out "su -c 'rm /system/xbin/tc /system/xbin/ts /system/xbin/uc /system/xbin/us /system/xbin/tls-block'"
	adb exec-out "su -c 'mount -o ro,remount /'"
