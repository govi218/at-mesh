# Headscale deployment examples

Example config files for running Headscale with at-mesh as the OIDC provider.

## Monitoring Headscale

at-mesh no longer proxies Headscale API requests. To manage Headscale
visually (nodes, ACLs, routes), run [headscale-ui](https://github.com/gurucomputing/headscale-ui)
separately and point it directly at your Headscale API endpoint.
