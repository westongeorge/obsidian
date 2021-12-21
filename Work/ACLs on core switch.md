#security 
~~Prevent RDP student > servers~~
~~Prevent SSH student and staff > servers~~
~~Prevent RDP staff > 10.x~~



ip access-list extended "Server Management"

*add these first*
997 permit ip 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255
998 permit tcp 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255
999 permit udp 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255

*then*
1 deny tcp 172.0.0.0 0.255.255.255 gt 1024 0.0.0.0 255.255.255.255 eq 3389
1 remark "Block Student > RDP"
5 deny tcp 172.0.0.0 0.255.255.255 gt 1024 00.0.0.0 255.255.255.255 eq 22
5 remark "Block Student > SSH"
10 deny tcp 172.0.0.0 0.255.255.255 gt 1024 0.0.0.0 255.255.255.255 eq 42224
10 remark "Block Student > alt SSH"
15 deny tcp 192.168.20.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 3389
15 remark "block Printers > mgmt RDP"
20 deny tcp 192.168.21.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 3389
20 remark "block es-staff > mgmt RDP"
25 deny tcp 192.168.22.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 3389
25 remark "block cp-staff > mgmt RDP"
30 deny tcp 192.168.23.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 3389
30 remark "block is-staff > mgmt RDP"
35 deny tcp 192.168.24.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 3389
35 remark "block ms-staff > mgmt RDP"
40 deny tcp 192.168.25.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 3389
40 remark "block hs-staff > mgmt RDP"
45 deny tcp 192.168.26.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 3389
45 remark "block tc-staff > mgmt RDP"
50 deny tcp 192.168.27.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 3389
50 remark "block co-staff > mgmt RDP"
55 deny tcp 192.168.20.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
55 remark "block Printers > mgmt ssh"
60 deny tcp 192.168.21.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
60 remark "block es-staff > mgmt ssh"
75 deny tcp 192.168.22.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
75 remark "block cp-staff > mgmt ssh"
80 deny tcp 192.168.23.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
80 remark "block is-staff > mgmt ssh"
85 deny tcp 192.168.24.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
85 remark "block ms-staff > mgmt ssh"
90 deny tcp 192.168.25.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
90 remark "block hs-staff > mgmt ssh"
95 deny tcp 192.168.26.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
95 remark "block tc-staff > mgmt ssh"
100 deny tcp 192.168.27.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
100 remark "block co-staff > mgmt ssh"
105 deny tcp 192.168.20.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 22
105 remark "block Printers > mgmt ssh"
110 deny tcp 192.168.21.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 42224
110 remark "block es-staff > alt ssh"
115 deny tcp 192.168.22.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 42224
115 remark "block cp-staff > alt ssh"
120 deny tcp 192.168.23.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 42224
120 remark "block is-staff > alt ssh"
125 deny tcp 192.168.24.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 42224
125 remark "block ms-staff > alt ssh"
130 deny tcp 192.168.25.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 42224
130 remark "block hs-staff > alt ssh"
135 deny tcp 192.168.26.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 42224
135 remark "block tc-staff > alt ssh"
140 deny tcp 192.168.27.0 0.0.0.255 gt 1024 10.0.0.0 0.255.255.255 eq 42224
140 remark "block co-staff > alt ssh"

