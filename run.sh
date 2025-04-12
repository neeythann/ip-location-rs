# NOTE: please read DPIP-LICENSE and ROUTEVIEWS-LICENSE before continuing
# This bash script is ONLY invoked in the starting point of the docker container

wget https://cdn.jsdelivr.net/npm/@ip-location-db/asn-country-mmdb/asn-country-ipv4.mmdb
wget https://cdn.jsdelivr.net/npm/@ip-location-db/asn-country-mmdb/asn-country-ipv6.mmdb
wget https://cdn.jsdelivr.net/npm/@ip-location-db/asn-mmdb/asn-ipv4.mmdb
wget https://cdn.jsdelivr.net/npm/@ip-location-db/asn-mmdb/asn-ipv6.mmdb
/app/ip-location-rs
