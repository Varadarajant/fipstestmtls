# fipstestmtls
FIPS BCFKS Test with Standalone mTLS server

This code is modified code from  Bouncy castle to test BCFKS store format. 

Initially I was working with wildfly server with BCFKS trust store but that is not working. So I want to isolate the case. So took the Bouncy castle sample and modified the code to create a standalone Mutal TLS server loaded with BCFKS truststore format and that works fine. Just sharing that code.
