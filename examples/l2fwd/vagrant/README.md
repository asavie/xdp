# l2fwd test environment

This directory contains Vagrant configuration files which will bring up a test
environment for [l2fwd](https://github.com/asavie/xdp/examples/l2fwd/l2fwd.go).

The enviornment consists of 3 virtual machines, 'Server', where you run the
`iperf` server, 'Client' where you run the `iperf` client and 'L2fwd', where
you run `l2fwd`.

'Client' and 'Server', in addition to the usual NAT interface, each have their
own additional 'Internal Network' interface.
'L2fwd' has two additional 'Internal Network' interfaces, one in 'Client'
network and one in 'Server' network. Thus 'L2fwd' is able to bridge the
networks between 'Client' and 'Server'.

# How to deploy

1. Install Vagrant, e.g. on Fedora Linux: `sudo dnf install vagrant`.
2. Run `vagrant up` in each of the `server`, `client` and `l2fwd` directories.
3. Log into each machine by running `vagrant ssh` in corresponding directory
   and run the command that was printed at the end of provisioning in previous
   step.
