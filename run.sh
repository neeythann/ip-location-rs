# NOTE: please read DPIP-LICENSE and ROUTEVIEWS-LICENSE before continuing
# This bash script is ONLY invoked in the starting point of the docker container
#
# PROXY_TYPE can be set in the container environment to configure which
# header ip-location-rs trusts for the client's real IP on the index
# endpoint (cf-connecting-ip, x-forwarded-for, x-real-ip, or none). It is
# read natively by the binary via clap's env support, so it just needs to
# be present in the environment when /app/ip-location-rs runs.

wget https://cdn.jsdelivr.net/npm/@ip-location-db/asn-country-mmdb/asn-country-ipv4.mmdb
wget https://cdn.jsdelivr.net/npm/@ip-location-db/asn-country-mmdb/asn-country-ipv6.mmdb
wget https://cdn.jsdelivr.net/npm/@ip-location-db/asn-mmdb/asn-ipv4.mmdb
wget https://cdn.jsdelivr.net/npm/@ip-location-db/asn-mmdb/asn-ipv6.mmdb
/app/ip-location-rs
