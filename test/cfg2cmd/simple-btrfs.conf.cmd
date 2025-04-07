/usr/bin/kvm \
  -id 8006 \
  -name 'simple,debug-threads=on' \
  -no-shutdown \
  -chardev 'socket,id=qmp,path=/var/run/qemu-server/8006.qmp,server=on,wait=off' \
  -mon 'chardev=qmp,mode=control' \
  -chardev 'socket,id=qmp-event,path=/var/run/qmeventd.sock,reconnect-ms=5000' \
  -mon 'chardev=qmp-event,mode=control' \
  -pidfile /var/run/qemu-server/8006.pid \
  -daemonize \
  -smbios 'type=1,uuid=7b10d7af-b932-4c66-b2c3-3996152ec465' \
  -smp '3,sockets=1,cores=3,maxcpus=3' \
  -nodefaults \
  -boot 'menu=on,strict=on,reboot-timeout=1000,splash=/usr/share/qemu-server/bootsplash.jpg' \
  -vnc 'unix:/var/run/qemu-server/8006.vnc,password=on' \
  -cpu kvm64,enforce,+kvm_pv_eoi,+kvm_pv_unhalt,+lahf_lm,+sep \
  -m 768 \
  -global 'PIIX4_PM.disable_s3=1' \
  -global 'PIIX4_PM.disable_s4=1' \
  -device 'pci-bridge,id=pci.1,chassis_nr=1,bus=pci.0,addr=0x1e' \
  -device 'pci-bridge,id=pci.2,chassis_nr=2,bus=pci.0,addr=0x1f' \
  -device 'vmgenid,guid=c773c261-d800-4348-1010-1010add53cf8' \
  -device 'piix3-usb-uhci,id=uhci,bus=pci.0,addr=0x1.0x2' \
  -device 'usb-tablet,id=tablet,bus=uhci.0,port=1' \
  -device 'VGA,id=vga,bus=pci.0,addr=0x2' \
  -device 'virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x3,free-page-reporting=on' \
  -iscsi 'initiator-name=iqn.1993-08.org.debian:01:aabbccddeeff' \
  -drive 'if=none,id=drive-ide2,media=cdrom,aio=io_uring' \
  -device 'ide-cd,bus=ide.1,unit=0,drive=drive-ide2,id=ide2,bootindex=200' \
  -device 'virtio-scsi-pci,id=scsihw0,bus=pci.0,addr=0x5' \
  -drive 'file=/butter/bread/images/8006/vm-8006-disk-0/disk.raw,if=none,id=drive-scsi0,discard=on,format=raw,aio=io_uring,detect-zeroes=unmap' \
  -device 'scsi-hd,bus=scsihw0.0,channel=0,scsi-id=0,lun=0,drive=drive-scsi0,id=scsi0,bootindex=100' \
  -netdev 'type=tap,id=net0,ifname=tap8006i0,script=/var/lib/qemu-server/pve-bridge,downscript=/var/lib/qemu-server/pve-bridgedown,vhost=on' \
  -device 'virtio-net-pci,mac=A2:C0:43:77:08:A0,netdev=net0,bus=pci.0,addr=0x12,id=net0,rx_queue_size=1024,tx_queue_size=256,bootindex=300' \
  -machine 'type=pc+pve1'
