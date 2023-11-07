# Lab01 - Packet Processing

Given a computer equipped with a packet capture library (e.g., libpcap or WinPcap), write a program
in C/C++ language that:
 - Captures all the packets generated and received by the host;
 - Writes, per each packet, a single line on screen reporting the following information (in case some
information are not available, such as the PORT in case of a packet that is neither UDP nor
TCP, please leave the field blank):
timestamp MAC_src -> MAC_dst IP_src -> IP_dst Protocol PORT_src -> PORT_dst
 - Check if the TCP the destination port of the packet is equal to `80'; in this case:
{ Check if the packet contains an HTTP request (e.g., a POST/GET command)
{ In this case, extract the URL contained in the packet (e.g., www.cnn.com) and print it on
screen, after the data mentioned before.
Please note that the URI of an HTTP request message can be specified in different forms (e.g.
absolute URI, absolute path, etc.) and some of them may refer to the Host header field. For the
purpose of this exercise the student is asked to print on screen a single line that concatenates the text
present in the Host field with the URL contained on the Request line, such as:
begincode www.cnn.com/weather

## Usage

```c
gcc readfile-ex.c -o readfile-ex -lpcap

sudo ./readfile-ex

```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.