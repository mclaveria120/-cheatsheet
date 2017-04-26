 
# Setup and Configure SSl

1. Create keyStore:
 * keytool -genkey -keysize 2048 -keyalg RSA -alias tomcat -keystore myKeyStore
     - The information that we need to include:
         + Common Name: domain name of the website.
     - Remember:
         + alias
         + keystore name
         + password used.
     - These will be used later.
2. Create csr:
 * keytool -certreq -alias tomcat -keyalg RSA -file certreq.csr -keystore myKeyStore
3. Send the crt to the Certificate Authority.
4. We will receive a certificate: myCertificate.crt
5. Make a copy of the keyStore somewhere.
6. Import that certificate as well as the root and intermediate certificate in the following order. If you dont respect the order it will fails:
 * keytool -import --alias root -trustcacerts -file root.crt  -keystore myKeyStore
 * keytool -import --alias inter1 -trustcacerts -file inter1.crt  -keystore myKeyStore
 * keytool -import --alias inter2 -trustcacerts -file inter2.crt  -keystore myKeyStore 
 * keytool -import --alias tomcat   -trustcacerts -file myCertificate.crt  -keystore myKeyStore


# Tomcat 

```
<Connector port="9443" protocol="HTTP/1.1" SSLEnabled="true"
               maxThreads="150" scheme="https" secure="true"
               keystoreFile="myKeyStore"
               keystorePass="password"
               keyAlias="tomcat"
               clientAuth="false" sslProtocol="TLS" />
```


# GET PRIVATE KEY FROM KEYSTORE
* keytool -importkeystore -srckeystore myKeyStore.jks -destkeystore myKeyStore.p12 -deststoretype PKCS12
* openssl pkcs12 -in myKeyStore.p12
 * Export the certificate: 
    - openssl pkcs12 -in myKeyStore.p12 -nokeys -out cert.pem
 * Export the private key (unencrypted)
    - openssl pkcs12 -in myKeyStore.p12  -nodes -nocerts -out privateKey.pem

# IPTABLES
* sudo iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 9443
* sudo iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
 
# Useful commands:
* keytool -list -keystore csye
* sudo iptables -A INPUT -i eth0 -p tcp --dport 80 -j ACCEPT
* sudo iptables -L --line-number
* sudo iptables -L -vt nat
* sudo iptables -t nat -D PREROUTING 4
* sudo iptables -D INPUT 4
 

