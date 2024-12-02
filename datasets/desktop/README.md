# Desktop Applications

This folder contains PCAP and CSV files with communications captured by the [HashApp tool](https://hashapp.netology.sk/), which emulates mobile applications in APK format. The mobile applications have been emulated on Android 11, 13 and 14. Each application has been run three times. The Android version and the number of run are indicated by the file name (e.g., accuweather_01-11.csv indicates the first run of the Accuweather app on Android 11). If no TLS communication was captured during the application run, the CSV file will be empty.

Some PCAP files have been omitted due to the Github file size limitations. However, the full record of TLS sessions is available in the corresponding CSV files.

# A list mobile applications
* accuweather
* aliexpress
* alipay
* alza
* capcut
* chatgpt
* discord
* disney-plus
* facebook
* foodora
* gmail
* google-play
* instagram
* mapy-cz
* messenger
* muj-vlak
* netflix
* packeta
* reddit
* regiojet
* shein
* signal
* snapchat
* spotify
* telegram
* temu
* tiktok
* trello
* twitter
* viber
* waze
* wechat
* whatsapp
* wolt
* youtube

## CSV raw file format - a sequence of TLS connections
   1. **SrcIP**: TLS client IP address
   2. **DstIP**: TLS server IP address
   3. **SrcPort**: TLS client port number
   4. **DstPort**: TLS server port number
   5. **Proto**: Transport protocol (UDP or TCP)
   6. **SNI**: Server Name Indication (TLS extension)
   7. **OrgName**: Organization Name corresponding to the IP address space of the server, extracted from the WHOIS database
   8. **TLS Version**: TLS handshake version
   9. **Client CipherSuite**: A list of client cipher suites offered during the TLS handshake.
   10. **Client Extensions**: A list of client extensions offered during the TLS handshake.
   11. **Client Supported Groups**: A list of supported groups (TLS extension no. 10). 
   12. **EC_fmt**: a list of Elliptic Curve formats (TLS extension no. 11).
   13. **ALPN**: Extracted data from the Application Layer Protocol Negotiation field (TLS extension no. 16)
   14. **Signature Algorithms**: a set of signature algorithms supported by the TLS server (TLS extension no. 13)
   15. **Client Supported Versions**: A set of TLS versions supported by the TLS client (TLS extension no. 43)
   16. **JA3hash**: JA3 client fingerprint computed as defined by [John Althouse et al.](https://medium.com/salesforce-engineering/tls-fingerprinting-with-ja3-and-ja3s-247362855967). 
   17. **JA4 hash**: JA4 client fingerprint computed as defined by [John Althouse et al.](https://blog.foxio.io/ja4+-network-fingerprinting).
   18. **JA4_raw**: A raw format of the JA4 fingerprint (before hashing).
   19. **AppName**: Application name (annotation).
   20. **Type**: 0 (normal application) / M (malware) / A (advertising/analytics server).
   21. **Server CipherSuite**: A cipher suite selected by the server during the TLS handshake. 
   22. **Server Extensions**: Extensions selected by the server during the TLS handshake.
   23. **Server Supported Versions**: TLS versions supported by the TLS server (TLS extension no. 43). 
   24. **JA3S hash**: JA3s server fingerprint computed as defined by [John Althouse et al.](https://blog.foxio.io/ja4+-network-fingerprinting)..
   25. **JA4S hash**: JA4s server fingerprint computed as defined by [John Althouse et al.](https://blog.foxio.io/ja4+-network-fingerprinting)..
   26. **JA4S_raw**: A raw format of the JA4 fingerprint (before hashing).
   27. **Filename**: A name of the PCAP file containg the processed captured traffic. 
   28. **Version**: A version of the application (not used, 0).


