# Automated TCP measurements

between two systems, with and without ssh tunneling

## Preparation: simple connection test
To check if a TCP connection exists, run
```
netcat -l -p 9999
```
on the receiver (to make sure the port is not in use yet) and
```
echo hallo | netcat $RECEIVER_IP 9999
```
on the sending system.

In case you have not opened port 9999, the firewall of the receiver will
typically block this connection. 

If you want to check the sending of TPC packets through an ssh tunnel 
(e.g., if the receiver is only visible behind a login node),
you may establish the port connection by running
```
ssh -L 9999:$RECEIVER_IP:9999 $RECEIVER_LOGIN_NODE -nNT &
```
on the sender before starting netcat. The `$RECEIVER_IP` in the `netcat` call 
then becomes `localhost`.


# Roundtrip Time Tests

for the current setup (opened port 9999 on receiver 
for connections from sender), execute 
```
python3 RTTTest.py -r -p 9999 -s 1000,10000
```
on the receiver and
```
python3 RTTTest.py -r $RECEIVER_IP -p 9999 -s 1000,10000
```
on the sender. The last numbers specify the data size to test (in bytes).
