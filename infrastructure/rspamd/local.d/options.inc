# Use the in-network DNS resolver; never reach out to public DoH by default.
dns {
  timeout = 2s;
  retransmits = 2;
}
