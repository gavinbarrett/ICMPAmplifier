## ICMP Barrage
ICMP Barrage is a simple tool for spoofing network addresses and carrying out smurf attacks.

### What is a smurf attack?
A smurf attack is an elegant variation of a DDoS attack; the analogy is that of a bunch of little entities (smurfs) overpowering their foe through sheer numbers.

This attack works by sending numerous ICMP ping echo requests to a bunch of different systems, with an important caveat: all packets have their source IP spoofed to be that of the victim. You've likely used a ping command to send echo requests to systems before and noticed the continuous stream of bytes that is returned to the user. By spoofing the source IP address of our requests, we will direct all of this traffic to go to our victim.
