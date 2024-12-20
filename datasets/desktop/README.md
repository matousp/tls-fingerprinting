# Desktop Applications

This folder contains PCAP files and CSV files containing communications from a specific MS Window application. MS Window desktop communication samples were obtained by running Windows applications and services, and capturing their communication using tshark. Each application was tested with multiple runs, so each file name contains the date of the run, e.g., AirDroidAirDroid_20240722.pcap indicates AirDroid application running on 22/7/2024. The captured communication was later annotated by process names obtained by observing the connected ports on the desktop.

Some PCAP files have been omitted due to the Github file size limitations. However, the full record of TLS sessions is available in the corresponding CSV files.

# A list of desktop applications and process names
* Messenger - AdmntMessenger
* AirDroid - AirDroidAirDroid
* AsnAsn
* BeeerBeeer
* BidBox - BiduTerBox
* BiglyBT Bittorrent Client - BiglySoftwreBiglyBT
* Brave Browser - BrveBrve
* CloudAGCloudDrive
* Cozy Cloud - CozyCloudCozyDrive
* CrineCrine
* Deezer - DeezerDeezer
* Send Anywhere - EstmobSendAnywhere
* Evernote - EvernoteEvernote
* GoogleChrome - GoogleChrome
* HedsetHedset
* LINELINE
* MegMEGASyn
* MehediHssnTweeten
* MilbirdMilbird
* MS Edge - MirosoftEdge
* Firefox - MozillFirefox
* Thunderbird - MozillThunderbird
* Nextcloud - NextloudNextloudDeskto
* NotionNotion
* NotionNotionClendr
* OenMedi4KStogrm
* OenMedi4KTokkit
* OenWhiserSystemsSignl
* OerOer
* Proton Drive - ProtonProtonDrive
* Viber - RkutenViber
* SlkTehnologiesSlk
* SlshedIoInssist
* SotifySotify
* TIDALMusiASTIDAL
* Telegram - TelegrmTelegrmDeskto
* TemDriveSystemsTemDrive
* TemSonrrSonrr
* TrillinTrillin
* TymnixEletorrent
* YndexMessenger
* Zoom - ZoomZoom
* eMClienteMClient

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
   24. **JA3S hash**: JA3s server fingerprint computed as defined by [John Althouse et al.](https://blog.foxio.io/ja4+-network-fingerprinting).
   25. **JA4S hash**: JA4s server fingerprint computed as defined by [John Althouse et al.](https://blog.foxio.io/ja4+-network-fingerprinting).
   26. **JA4S_raw**: A raw format of the JA4 fingerprint (before hashing).
   27. **Filename**: A name of the PCAP file containg the processed captured traffic. 
   28. **Version**: A version of the application (not used, 0).


