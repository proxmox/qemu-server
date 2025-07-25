/usr/bin/kvm \
  -id 8006 \
  -name 'vm8006,debug-threads=on' \
  -no-shutdown \
  -chardev 'socket,id=qmp,path=/var/run/qemu-server/8006.qmp,server=on,wait=off' \
  -mon 'chardev=qmp,mode=control' \
  -chardev 'socket,id=qmp-event,path=/var/run/qmeventd.sock,reconnect-ms=5000' \
  -mon 'chardev=qmp-event,mode=control' \
  -pidfile /var/run/qemu-server/8006.pid \
  -daemonize \
  -smbios 'type=1,uuid=7b10d7af-b932-4c66-b2c3-3996152ec465' \
  -object '{"id":"throttle-drive-efidisk0","limits":{},"qom-type":"throttle-group"}' \
  -blockdev '{"driver":"raw","file":{"driver":"file","filename":"/usr/share/pve-edk2-firmware//OVMF_CODE.fd"},"node-name":"pflash0","read-only":true}' \
  -blockdev '{"detect-zeroes":"on","discard":"ignore","driver":"throttle","file":{"cache":{"direct":true,"no-flush":false},"detect-zeroes":"on","discard":"ignore","driver":"raw","file":{"aio":"io_uring","cache":{"direct":true,"no-flush":false},"detect-zeroes":"on","discard":"ignore","driver":"file","filename":"/tmp/8006-ovmf.fd","node-name":"e5b5f7a29888341a35f0f1428e70ba5","read-only":false},"node-name":"f5b5f7a29888341a35f0f1428e70ba5","read-only":false,"size":131072},"node-name":"drive-efidisk0","read-only":false,"throttle-group":"throttle-drive-efidisk0"}' \
  -smp '1,sockets=1,cores=1,maxcpus=1' \
  -nodefaults \
  -boot 'menu=on,strict=on,reboot-timeout=1000,splash=/usr/share/qemu-server/bootsplash.jpg' \
  -vnc 'unix:/var/run/qemu-server/8006.vnc,password=on' \
  -cpu kvm64,enforce,+kvm_pv_eoi,+kvm_pv_unhalt,+lahf_lm,+sep \
  -m 512 \
  -global 'PIIX4_PM.disable_s3=1' \
  -global 'PIIX4_PM.disable_s4=1' \
  -device 'pci-bridge,id=pci.1,chassis_nr=1,bus=pci.0,addr=0x1e' \
  -device 'pci-bridge,id=pci.2,chassis_nr=2,bus=pci.0,addr=0x1f' \
  -device 'piix3-usb-uhci,id=uhci,bus=pci.0,addr=0x1.0x2' \
  -device 'usb-tablet,id=tablet,bus=uhci.0,port=1' \
  -device 'VGA,id=vga,bus=pci.0,addr=0x2' \
  -device 'virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x3,free-page-reporting=on' \
  -iscsi 'initiator-name=iqn.1993-08.org.debian:01:aabbccddeeff' \
  -machine 'pflash0=pflash0,pflash1=drive-efidisk0,type=pc+pve0'
