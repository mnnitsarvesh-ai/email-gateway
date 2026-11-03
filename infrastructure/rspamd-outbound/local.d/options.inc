# Short DNS timeouts; the signing path performs no DNS-dependent checks (see the disabled
# modules in this directory).
dns {
  timeout = 2s;
  retransmits = 2;
}
