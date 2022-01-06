#security 
~~Prevent RDP student > servers~~
~~Prevent SSH student and staff > servers~~
~~Prevent RDP staff > 10.x~~



ip access-list extended "Server Management"

*add these first*
9999 permit ip 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255
#9998 permit tcp 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255
#9999 permit udp 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255

*then*
1 deny tcp 172.0.0.0 0.255.255.255 gt 1024 0.0.0.0 255.255.255.255 eq 3389
1 remark "Block Student > RDP"
50 deny tcp 172.0.0.0 0.255.255.255 gt 1024 00.0.0.0 255.255.255.255 eq 22
50 remark "Block Student > SSH"
100 deny tcp 172.0.0.0 0.255.255.255 gt 1024 0.0.0.0 255.255.255.255 eq 42224
100 remark "Block Student > alt SSH"
150 deny tcp 192.168.20.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 3389
150 remark "block Printers > mgmt RDP"
200 deny tcp 192.168.21.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 3389
200 remark "block es-staff > mgmt RDP"
250 deny tcp 192.168.22.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 3389
250 remark "block cp-staff > mgmt RDP"
300 deny tcp 192.168.23.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 3389
300 remark "block is-staff > mgmt RDP"
350 deny tcp 192.168.24.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 3389
350 remark "block ms-staff > mgmt RDP"
400 deny tcp 192.168.25.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 3389
400 remark "block hs-staff > mgmt RDP"
450 deny tcp 192.168.26.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 3389
450 remark "block tc-staff > mgmt RDP"
500 deny tcp 192.168.27.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 3389
500 remark "block co-staff > mgmt RDP"
550 deny tcp 192.168.20.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
550 remark "block Printers > mgmt ssh"
600 deny tcp 192.168.21.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
600 remark "block es-staff > mgmt ssh"
750 deny tcp 192.168.22.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
750 remark "block cp-staff > mgmt ssh"
800 deny tcp 192.168.23.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
800 remark "block is-staff > mgmt ssh"
850 deny tcp 192.168.24.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
850 remark "block ms-staff > mgmt ssh"
900 deny tcp 192.168.25.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
900 remark "block hs-staff > mgmt ssh"
950 deny tcp 192.168.26.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
950 remark "block tc-staff > mgmt ssh"
1000 deny tcp 192.168.27.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
1000 remark "block co-staff > mgmt ssh"
1050 deny tcp 192.168.20.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
1050 remark "block Printers > mgmt ssh"
1100 deny tcp 192.168.21.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 42224
1100 remark "block es-staff > alt ssh"
1150 deny tcp 192.168.22.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 42224
1150 remark "block cp-staff > alt ssh"
1200 deny tcp 192.168.23.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 42224
1200 remark "block is-staff > alt ssh"
1250 deny tcp 192.168.24.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 42224
1250 remark "block ms-staff > alt ssh"
1300 deny tcp 192.168.25.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 42224
1300 remark "block hs-staff > alt ssh"
1350 deny tcp 192.168.26.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 42224
1350 remark "block tc-staff > alt ssh"
1400 deny tcp 192.168.27.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 42224
1400 remark "block co-staff > alt ssh"

