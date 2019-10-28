
# TLS

TLS Scanner

## BLEICHENBACHER_VULNERABLE

### Headline

Check for Bleichenbacher vulnerability <span class="promarker"></span>

### Category

Attacks

### Description

The server is vulnerable to a [[Bleichenbacher-Vulnerability/EN|Bleichenbacher attack]]. Communication can be decrypted and user entries such as passwords can be read.

### Background

The so-called Bleichenbacher attack (also known under the name ROBOT) is a 19 year old security flaw that allows RSA decryption and signature operations to be performed with the private key of a TLS server. The attack is an error in the program code.

### Consequence

The server is vulnerable through a security flaw that allows an attacker to decrypt the communication.

### Solution_Tips

If ''vulnerability'' has been reported, immediately install an update for your TLS Implementation on your server.

### Link

Bleichenbacher-Vulnerability

### Negative

Vulnerable to [https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Adaptive_chosen_ciphertext_attacks Bleichenbacher] (ROBOT).

### Positive

Not vulnerable to [https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Adaptive_chosen_ciphertext_attacks Bleichenbacher] (ROBOT).

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CERTIFICATE_EXPIRED

### Headline

Check of certificate validity period

### Category

Certificates

### Description

This message means that your [[Certificate|Server certificate]] has expired. Visitors will be warned that your website may be insecure or not trustworthy. If a visitor uses HTTPS to open your website, he or she may receive an error message, for example "Your certificate expired on (date)". The website will appear insecure or not trustworthy to visitors.

### Background

[[Certificate|Server certificates]] increase security on the internet and are used to verify websites. A [[Certificate|certificate]] is issued and verified by an official, trustworthy institution and verifies the identity of the website. A certificate cannot be forged. In everyday life, a certificate can be compared to an identity card or a notarized document. Similar to a passport, certificates are also valid for a certain period of time. Thus certificates make it possible to exchange data via secure connections and form an important basis of trust for operators of online shops.

### Consequence

In the standard settings, most Internet browser are configured so that websites with an expired [[Certificate|certificate]] are not trusted. A website with an expired certificate will generate a warning message whenever it is accessed. Some browser or plug-ins, depending on their configuration settings, can block access your website completely. If visitors to your website receive a warning message, this will have a negative effect on your company's presentation on the internet. If internet browser do not trust your website, why should your customers trust you? An expired SSL certificate will also have a negative effect on search engine rank. Your company may no longer be listed at the top of a search engine results page, and it may move down the page even further if the problem persists. Visitors may even be alerted in the search results that there is a security issue on your website.

### Solution_Tips

If ''Certificate expired'' was reported renew the [[Certificate|certificate]]. For information on how to renew a certificate, please refer to: [[Zertifikate#Was_tun.2C_wenn_ein_SSL-Zertifikat_abgelaufen_ist.3F|certificate expired (German only)]].

### Link

Certificate-Expired

### Negative

[[Certificate|Certificate]] expired

### Positive

[[Certificate|Certificate]] not expired

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CERTIFICATE_NOT_SENT_BY_SERVER

### Headline

Verification of certificate transmission

### Category

Certificates

### Description

The server has not sent a [[Certificate|certificate]]. This is unusual and should not occur. The server should check its [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS configuration] and, if necessary, disable anonymous [https://en.wikipedia.org/wiki/Cipher_suite cipher suites].

### Background

It is theoretically possible to configure a [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS server] so that it will not send a [[Certificate|certificate]] to identify itself and only encrypt without signing its public key. A client that wants to connect to the server cannot check whether it is really communicating with the server it expects. This type of configuration is very rare.

### Consequence

Without a [[Certificate|certificate]] for your website, attackers can listen in on your communication. Criminals could intercept your customers' personal data, such as passwords or credit card information.

### Solution_Tips

If ''Server does not send a certificate'' was reported, urgently update your [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS implementation]. Current software no longer allows this type of configuration.

### Link

Certificate-Not-Sent

### Negative

Server does not send a certificate

### Positive

Server sends a certificate

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CERTIFICATE_NOT_VALID_YET

### Headline

Check of certificate validity

### Category

Certificates

### Description

This message means that your [[Certificate|server certificate]] is not yet valid. Visitors will be warned that your website may be insecure or not trustworthy. If a visitor uses HTTPS to open your website, he or she may receive an error message.

### Background

[[Certificate|Server certificates]] increase security on the internet and are used to verify the authenticity of websites. A certificate is issued and verified by an official, trustworthy institution. A certificate cannot be forged. In everyday life, a certificate can be compared to an identity card or a notarized document. Similar to a passport, certificates are also valid for a certain period of time. Thus certificates make it possible to exchange data via secure connections and form an important basis of trust for operators of online shops.

### Consequence

In the standard settings, most Internet browser are configured so that websites with an expired [[Certificate|certificate]] are not trusted. A website with an expired certificate will generate a warning message whenever it is accessed. Some browsers or plug-ins, depending on their configuration settings, can even block access your website completely.
If visitors to your website receive a warning message, this will have a negative effect on your company's presentation on the internet. If internet browsers do not trust your website, why should your customers trust you? An expired SSL certificate will also have a negative effect on search engine rank. Your company may no longer be listed at the top of a search engine results page, and it may move down the page even further if the problem persists. Visitors may even be alerted in the search results that there is a security issue on your website.

### Solution_Tips

If ''Certificate is not yet valid'' was reported, insert your old [[Certificate|certificate]] as long as it is still valid. You can find out how to renew [[Certificate|certificates]], please refer to: [[Certificate-Expired/EN|certificate expired]].

### Link

Certificate-Not-Valid

### Negative

[[Certificate|Certificate]] is not yet valid

### Positive

[[Certificate|Certificate]] is already valid

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CERTIFICATE_WEAK_HASH_FUNCTION

### Headline

Check of the certificate's encryption strength

### Category

Certificates

### Description

This message means that your [[Certificate|server certificate]] has a weak hash algorithm. This can potentially cause it to be falsified and is displayed as insecure in many browsers.

### Background

[[Certificate|Server certificates]] increase security on the internet and are used to verify the identity of websites. A certificate is issued and verified by an official, trustworthy institution. A certificate cannot be forged - in case of a weak hash algorithm (encryption), it can be swapped by a third party. In everyday life, a certificate can be compared to an identity card or a notarized document. Similar to a passport, certificates are also valid for a certain period of time. Thus certificates make it possible to exchange data via secure connections and form an important basis of trust for operators of online shops.

### Consequence

In the worst case, a weak hash algorithm can lead to attackers creating a fake [[Certificate|certificate]] for your website and impersonating your website. This means that one server can impersonate another server. Criminals may be able to access your customers' personal information such as passwords or credit card information.

### Solution_Tips

If ''weak hash algorithm'' was reported, you should install a new [[Certificate|certificate]] with a secure hash function. For information on how to obtain a secure certificate, please refer to: [[Zertifikate#Wie_wird_ein_SSL-Zertifikat_installiert.3F|install certificates (German only)]].

### Link

Weak-Encryption

### Negative

Weak hash algorithm

### Positive

Strong hash algorithm is used

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CIPHERSUITEORDER_ENFORCED

### Headline

Check for responsible selection of encryption algorithms

### Category

Cryptography

### Description

Your web server/website is configured so that the encryption algorithms of the website visitor are preferred to those of your web server. Server should not leave the choice of encryption algorithms to your customers, but actively select strong connections.

### Background

Usually your server determines the encryption algorithms of the connection, not the other way around. Similar to the real world, you have house rules on your server - you define the rules, the guest has to follow them. You should not leave to chance whether your connections are secure.

### Consequence

You are leaving it to the visitor of your website to decide how securely you communicate.

### Solution_Tips

If "irresponsible selection of encryption algorithms" has been reported, configure your web server so that your web server determines the encryption algorithms for communication between your web page and the visitor's web browser.

### Link

Encryption-algorithm

### Negative

Irresponsible selection of encryption algorithms

### Positive

Responsible selection of encryption algorithms

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CIPHERSUITE_ANON

### Headline

Check for anonymous key exchange

### Category

Cryptography

### Description

Your web server/website is configured to allow connections without verifying the identity of your server.

### Background

The term [https://en.wikipedia.org/wiki/Cipher_suite cipher suite] stands for a collection of cryptographic methods (encryption of information). This collection contains the key exchange method, the signature method, the encryption, and cryptographic hash function. This combination of cryptographic components ensures that there is a secure connection for the communication between two parties, for example your browser and a web server or website. In the [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS] protocol (Transport Layer Security), the ([https://en.wikipedia.org/wiki/Cipher_suite cipher suite] (cryptographic method) determines which algorithms are used to establish a secure data connection, and it ensures that the connection is secure.

### Consequence

Your server is ready to establish very weak connections, which are vulnerable to Man-in-the-middle attacks. This can be used, for example, to read out passwords or credit card information and misuse them for criminal purposes.

### Solution_Tips

If ''Anonymous key exchange is supported'' is reported, disable "Anonymous key exchange" support in Encryption Methodology.

### Link

Key-Exchange-Method

### Negative

Anonymous key exchange supported

### Positive

Anonymous key exchange not supported

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CIPHERSUITE_DES

### Headline

Check for DES encryption

### Category

Cryptography

### Description

Your web server/website is configured to support the outdated DES encryption method ([https://en.wikipedia.org/wiki/Cipher_suite cipher suite]), which is regarded as insecure. This makes you vulnerable to [https://en.wikipedia.org/wiki/Man-in-the-middle_attack man-in-the-middle-attacks].

### Background

The term [https://en.wikipedia.org/wiki/Cipher_suite cipher suite] stands for a cryptographic protocol that contains the key exchange method, the signature method, the encryption, and cryptographic hash functions. This combination of cryptographic components ensures that there is a secure connection for the communication between two parties, for example your browser and a web server or website. In the [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS] protocol (Transport Layer Security), the cipher suite determines which algorithms are used to establish a secure data connection.

### Consequence

Attackers can use DES encryption to decrypt the communication between your website and your customer's browser, as DES does not offer sufficient security. This can be used, for example, to decrypt passwords, form data or credit card information and misuse them for criminal purposes.

### Solution_Tips

If ''Outdated DES encryption supported'' was reported, deactivate support for the DES encryption method in your web server software.

### Link

Weak-DES-Encryption

### Negative

Outdated DES encryption supported

### Positive

Outdated DES encryption not supported

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CIPHERSUITE_EXPORT

### Headline

Check for weak encryption functions

### Category

Cryptography

### Description

Your web server/website is configured to use intentionally insecure encryption methods. This allows to decrypt communication with your server using Man-in-the-middle attacks.

### Background

The term [https://en.wikipedia.org/wiki/Cipher_suite cipher suite] stands for a collection of cryptographic methods. This collection contains the key exchange method, the signature method, the encryption, and cryptographic hash functions. This combination of cryptographic components ensures that there is a secure connection for the communication between two parties, for example your browser and a web server or website. In the [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS] protocol (Transport Layer Security), the cipher suite determines which algorithms are used to establish a secure data connection, and it ensures that the connection is secure.

### Consequence

Attackers can use a weak encryption method to decode communication between your Web page and the browser of your customer without any problems. It can be used, for example, to read passwords, form data or credit card information and misuse them for criminal purposes.  This make possible Man-in-the-middle attacks.

### Solution_Tips

If ''Weak EXPORT encryption supported'' was reported, deactivate support for EXPORT encryption methods on the web server.

### Link

Weakened-Encryption-Protocol

### Negative

Weak EXPORT encryption supported

### Positive

Weak EXPORT encryption not supported

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CIPHERSUITE_NULL

### Headline

Check for NULL ciphers

### Category

Cryptography

### Description

Your web server/website is configured to allow unencrypted voice transmission via a secure channel. This makes you vulnerable to [https://en.wikipedia.org/wiki/Man-in-the-middle_attack man-in-the-middle-attacks].

### Background

The term Cipher Suite stands for a group of cryptographic functions that includes the key exchange procedure, signature procedure, encryption and cryptographic hash functions. This combination of cryptographic components ensures a secure connection between two parties, such as your browser and a web server/website. In the TLS protocol (Transport Layer Security), the Cipher Suite determines which algorithms should be used to establish a secure data connection.

### Consequence

If no encryption is used, attackers can easily decode the communication between your website and your customer's browser. In this way, information such as passwords, data entered in forms, or credit card information can be intercepted and misused for criminal purposes.

### Solution_Tips

If ''Insecure NULL ciphers supported'' was reported, deactivate support for NULL encryption methods.

### Link

Unencrypted-Communication

### Negative

Insecure NULL ciphers supported

### Positive

Insecure NULL ciphers not supported

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CIPHERSUITE_RC4

### Headline

Check for RC4 encryption method

### Category

Cryptography

### Description

Your web server/website is configured to continue supporting the RC4 encryption feature, which is now considered insecure. This weakens your connections and can lead to an attacker decrypting your data.

### Background

The long-established encryption algorithm RC4 has been considered insecure for many years. Security researchers are aware of many critical gaps. In 2015, the IETF (Internet Engineering Task Force) banned the use of RC4 for TLS Connections in [https://tools.ietf.org/html/rfc7465 RFC7465].

### Consequence

Attackers can use RC4 encryption to potentially decrypt the communication between your website and your customer's browser, as RC4 has known vulnerabilities. This can be used to read passwords, form data or credit card information and misuse them for criminal purposes.

### Solution_Tips

If ''Outdated RC4 encryption supported'' was reported, deactivate support for the RC4 encryption.

### Link

Insecure-Encryption-Function_RC4

### Negative

Outdated RC4 encryption supported

### Positive

Outdated RC4 encryption not supported

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CRIME_VULNERABLE

### Headline

Check for the CRIME vulnerability

### Category

Attacks

### Description

The server is vulnerable to [[CRIME-Vulnerability/EN|Crime]]. This allows an attacker to decode the communication.

### Background

The CRIME attack takes advantage of the fact that data compression can change the length of encrypted messages, and this provides conclusions about the plain text. This can be used by a skilled attacker to steal cookies, for example.

### Consequence

The server is vulnerable through a security flaw that allows an attacker to decrypt the communication.

### Solution_Tips

CRIME can be prevented by disabling the use of compression of data in TLS. Disable TLS Compression on your server.

### Link

CRIME-Vulnerability

### Negative

Vulnerable to [[CRIME-Vulnerability/EN|Crime]]

### Positive

Not vulnerable to [[CRIME-Vulnerability/EN|Crime]]

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## EARLYCCS_VULNERABLE

### Headline

Check for Early-CCS Vulnerability

### Category

Attacks

### Description

The server is vulnerable to the Early-CCS vulnerability. This vulnerability allows an attacker to decrypt communication and read user input such as passwords under special circumstances.

### Background

The Early-CCS vulnerability is an implementation vulnerability in a 2014 TLS software library. If you are affected by this vulnerability, you should urgently update your software. The vulnerability is relatively minor, but a clear indicator that you have not updated your software for at least 5 years and are therefore affected by more serious attacks.

### Consequence

The server is vulnerable to a vulnerability that allows an attacker to decrypt the communication in special situations. The software used is obsolete.

### Solution_Tips

If vulnerability has been reported, immediately install an update to your TLS implementation on your server.

### Link

Early-CCS-Vulnerability

### Negative

Vulnerable to Early-CCS vulnerability.

### Positive

Not vulnerable to Early-CCS vulnerability.

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## HEARTBLEED_VULNERABLE

### Headline

Check for the [https://en.wikipedia.org/wiki/Heartbleed Heartbleed] vulnerability. <span class="promarker"></span>

### Category

Attacks

### Description

The server is vulnerable to a Heartbleed attack. As a result, an attacker could read sensitive data from the server's working memory, such as private keys and customer data.

### Background

Heartbleed is described as the most serious security vulnerability of all time and has existed since 2011. The vulnerability exists in a software called OpenSSL, which is designed to protect the communication of data on the Internet via the TLS security protocol. The gap in OpenSSL has already been closed for several years.

### Consequence

The server is vulnerable through a security flaw which allows an attacker to gain access to your server.

### Solution_Tips

In case of vulnerability update your [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS] implementation on your server immediately.

### Link

Heartbleed-Vulnerability

### Negative

Vulnerable to [[Heartbleed-Vulnerability/EN|Heartbleed]]

### Positive

Not vulnerable to [[Heartbleed-Vulnerability/EN|Heartbleed]]

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## HTTPS_NOT_SUPPORTED

### Headline

Check for HTTPS support

### Category

Information

### Description

The server does not seem to support [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS] (Transport Layer Security). This means that you are not using encryption to protect your own and your customers' data.

### Background

The server “:HOST“ does not seem to support [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS] (Transport Layer Security). This means that you are not using encryption to protect your own and your customers' data.

### Consequence

Everyone can read your data or manipulate the content of your website during transmission.

### Solution_Tips

If ''Server does not seem to speak TLS'' was reported, activate [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS] (Transport Layer Security).

### Link

No-TLS-Support

### Negative

Server does not seem to speak [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS].

### Positive

Server speaks [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS].

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## HTTPS_NO_RESPONSE

### Headline

Check for HTTPS support

### Category

Information

### Description

The server does not seem to respond. Have you entered the [[Domain]] correctly?

### Background

The server does not seem to respond. Have you entered the domain correctly?

### Consequence

The website could not be reached.

### Solution_Tips

If the server does not respond, please check your input for typing errors.

### Link

Response-Time-Exceeded

### Negative

Server does not respond.

### Positive

Server responds.

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## INVALID_CURVE_EPHEMERAL_VULNERABLE

### Headline

Check for the Ephemeral Invalid Curve vulnerability. <span class="promarker"></span>

### Category

Attacks

### Description

The server is vulnerable to an [[Invalid-Curve-Ephemeral-Vulnerability/EN|Ephemeral Invalid Curve Angriff]]. This allows an attacker to attack connections.

### Background

Elliptic Curve Cryptography (ECC) is one of the cornerstones of modern cryptography due to its security and performance features. It is used in key exchange protocols and to calculate signatures. However, fatal security holes can occur if it is used incorrectly.

### Consequence

The server is vulnerable through an implementation vulnerability that allows an attacker to decrypt the communication.

### Solution_Tips

If vulnerability was reported, update your [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS] implementation on your server immediately.

### Link

Invalid-Curve-Ephemeral-Vulnerability

### Negative

Vulnerable by [[Invalid-Curve-Ephemeral-Vulnerability/EN|Ephemeral Invalid Curve attacks]].

### Positive

Not vulnerable to [[Invalid-Curve-Ephemeral-Vulnerability/EN|Ephemeral Invalid Curve attacks]].

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## INVALID_CURVE_VULNERABLE

### Headline

Check for the Invalid Curve vulnerability. <span class="promarker"></span>

### Category

Attacks

### Description

The server is vulnerable to an Invalid Curve attack. This allows an attacker to steal the secret key of your certificate. After that, all your future connections will also be compromised, as well as parts of your past communication.

### Background

For cryptographic encryption, elliptic curves must be selected very carefully because the keys are created from certain points on a curve, which is not easy to do.

### Consequence

The server is vulnerable through an implementation vulnerability that allows an attacker to decrypt the communication and to steal the private key of your [[Certificate|certificate]].

### Solution_Tips

If vulnerabilities have been reported, immediately install an update to your TLS implementation on your server.  You should also replace your certificate, as it may already have been compromised.

### Link

Invalid-Curve-Vulnerability

### Negative

Vulnerable to [[Invalid-Curve-Vulnerability/EN|Invalid Curve attacks]].

### Positive

Not vulnerable to [[Invalid-Curve-Vulnerability/EN|Invalid Curve attacks]].

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## PADDING_ORACLE_VULNERABLE

### Headline

Check for the Padding Oracle vulnerability. <span class="promarker"></span>

### Category

Attacks

### Description

The server is vulnerable to a Padding Oracle attack, which allows an attacker to decrypt the communication.

### Background

A [[Padding-Oracle-Vulnerability/EN|Padding Oracle attack]] is a cryptographic attack that decrypts an encrypted message. For this he sets up a connection to the server and sends very specially prepared encrypted messages. These messages are almost correctly encrypted, but have incorporated errors at crucial positions. A server receiving such a message must always '''reject these messages in the same way'''. An attacker evaluates the sent error messages and can use These informations, if necessary, to partially decrypt the connection to the server, which makes the connection unsafe.

### Consequence

The server is vulnerable through an implementation vulnerability that allows an attacker to decrypt the communication.

### Solution_Tips

If vulnerability was reported, update your [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS] implementation on your server immediately.

### Link

Padding-Oracle-Vulnerability

### Negative

Vulnerable to [[Padding-Oracle-Vulnerability/EN|Padding Oracle attacks]].

### Positive

Not vulnerable to [[Padding-Oracle-Vulnerability/EN|Padding Oracle attacks]].

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## POODLE_VULNERABLE

### Headline

Check for the POODLE vulnerability

### Category

Attacks

### Description

The server is vulnerable to a POODLE attack, which allows an attacker to decrypt the communication.

### Background

[https://en.wikipedia.org/wiki/POODLE POODLE attack] (Padding Oracle On Downgraded Legacy Encryption) is a serious security flaw in various internet protocols, whereby private data from clients and servers can be read via encrypted connections.

### Consequence

The server is vulnerable through a security flaw that allows an attacker to decrypt the communication.

### Solution_Tips

If vulnerability was reported, deactivate the outdated encryption protocol SSL3 on your server immediately!

### Link

POODLE-Vulnerability

### Negative

Vulnerable to [https://en.wikipedia.org/wiki/POODLE POODLE]

### Positive

Not vulnerable to [https://en.wikipedia.org/wiki/POODLE POODLE]

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## PROTOCOLVERSION_SSL2

### Headline

Check for outdated SSL2 protocol

### Category

Cryptography

### Description

The server supports the outdated protocol version SSL2, which is considered to be highly insecure. By using this version, you massively compromise the security of the server and possibly your entire company network.

### Background

[https://en.wikipedia.org/wiki/Transport_Layer_Security SSL] (Secure Sockets Layer) stands for a hybrid (combined) encryption protocol for secure data transmission on the internet, it forms the basis for secure connections via HTTPS. The version SSL2 was first introduced in 1994 and is no longer supported officially since 2011. The name SSL has been replaced by TLS (Transport Layer Security). The SSL2 security flaw is used, for example, as a gateway for [https://www.heise.de/security/meldung/DROWN-Angriff-SSL-Protokoll-aus-der-Steinzeit-wird-Servern-zum-Verhaengnis-3121121.html DROWN attack: SSL protocol from the Stone Age is fatal to servers (German only)], which allows criminals to intercept the entire data communication of your website.

### Consequence

SSL2 is no longer supported by almost all Internet browsers, but still leads to fatal security problems on your website. SSL2 is one of the oldest components of the Internet and must be switched off immediately. Search engines will potentially penalize your website for using SSLv2.

### Solution_Tips

If ''Outdated protocol version SSL2 supported'' was reported: [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS encoding] is considered to be the standard today. Therefore you should not use SSL2.

### Link

Outdated-Protocol-Version-SSL2

### Negative

Outdated protocol version SSL2 supported.

### Positive

Outdated protocol version SSL2 not supported.

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## PROTOCOLVERSION_SSL3

### Headline

Check for outdated SSL3 protocol

### Category

Cryptography

### Description

The server supports the outdated SSL3 protocol version, which is considered highly insecure. By using this version you massively endanger the security of the connections to this server.

### Background

SSL (Secure Sockets Layer) stands for a hybrid encryption protocol for secure data transmission on the Internet and serves as the basis for secure access via HTTPS. The SSL3 version dates from 1995 and has not been officially supported since 2015. The term SSL has since been replaced by the term TLS (Transport Layer Security). The SSL3 gap became particularly known through POODLE. By using SSL3, the confidentiality of the connections can no longer be guaranteed.

### Consequence

By offering SSL3 on the server side, you allow attacks on connections with older clients. This allows an attacker to potentially decrypt parts of the connection and steal customer data.

### Solution_Tips

If ''Outdated protocol version SSL3 supported'' was reported: [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS] encoding is considered to be the standard today. Therefore you should not use SSL3.

### Link

Outdated-Protocol-Version-SSL3

### Negative

Outdated protocol version SSL3 supported.

### Positive

Outdated protocol version SSL3 not supported.

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## PROTOCOLVERSION_TLS13

### Headline

Check for use of the [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS 1.3 protocol]

### Category

Cryptography

### Description

The server supports the latest [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS 1.3 protocol version]. This version is still going through the standardisation process. If you do not understand what this means, you can deactivate the version, because most browsers do not yet support this version, and TLS 1.3 is still in development.

### Background

TLS 1.3 is the latest version of TLS. It is faster and better.

### Consequence

[https://en.wikipedia.org/wiki/Transport_Layer_Security TLS 1.3] is not supported by any internet browser in the standard configuration, so you will not win or lose any customers if you do not support this version.

### Solution_Tips

There is no need for action.

### Link

Protocol-Version-TLS13-Found

### Negative

Modern [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS 1.3 protocol] supported.

### Positive

[https://en.wikipedia.org/wiki/Transport_Layer_Security TLS 1.3 protocol] not supported.

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## SWEET32_VULNERABLE

### Headline

Check for the Sweet32 vulnerability

### Category

Attacks

### Description

The server is vulnerable to Sweet32, which allows an attacker under certain circumstances to decrypt parts of the communication if large amounts of data are transferred over a connection.

### Background

The attack exploits 64-bit block ciphers. The Sweet32 attack allows an attacker, under certain circumstances, to recover small pieces of text when encrypted with 64-bit block ciphers (such as 3DES). The attack is not very easy to perform, so the threat is limited.

### Consequence

The server is vulnerable through Sweet32, which allows an attacker to decrypt the communication.

### Solution_Tips

Wherever possible, it is best not to use triple DES. Deactivate block ciphers with a block length of 64 bits.

### Link

Sweet32-Vulnerability

### Negative

Vulnerable to [https://en.wikipedia.org/wiki/Sweet32 Sweet32].

### Positive

Not vulnerable to [https://en.wikipedia.org/wiki/Sweet32 Sweet32].

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## TLS_POODLE_VULNERABLE

### Headline

Check for the TLS-POODLE vulnerability

### Category

Attacks

### Description

The server is vulnerable to a variant of the [https://en.wikipedia.org/wiki/POODLE POODLE attack] on [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS], which allows an attacker to decrypt the communication.

### Background

There is a variant of the POODLE attack which also attacks newer TLS versions. This is possible due to an implementation error in the TLS servers.

### Consequence

The server is vulnerable through an vulnerability that allows an attacker to decrypt the communication.

### Solution_Tips

If vulnerability was reported, update the TLS implementation on your server immediately.

### Link

TLS-POODLE-Vulnerability

### Negative

Vulnerable to [https://en.wikipedia.org/wiki/POODLE TLS POODLE].

### Positive

Not vulnerable to [https://en.wikipedia.org/wiki/POODLE TLS POODLE].

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## _RESULTS

### ANON_SUITES

Your web server/website is configured to make connections using an anonymous encryption method ([https://en.wikipedia.org/wiki/Cipher_suite cipher suite]) without authentication. This makes you vulnerable to [https://en.wikipedia.org/wiki/Man-in-the-middle_attack man-in-the-middle-attacks].

### CERTIFICATE_WEAK_SIGN_ALGO

Check of certificate encryption

### CERTIFICATE_WEAK_SIGN_ALGO_SUCCESS

Check of certificate encryption

### DES_SUITES

Your web server/website is configured to support the outdated DES encryption method ([https://en.wikipedia.org/wiki/Cipher_suite cipher suite]), which is regarded as insecure. This makes you vulnerable to [https://en.wikipedia.org/wiki/Man-in-the-middle_attack man-in-the-middle-attacks].

### EXPIRED

Your [[Certificate|certificate]] expired on :DATE. Visitors will be warned that your website may be insecure or not trustworthy.

### EXPORT_SUITES

Your web server/website is configured to support intentionally insecure encryption methods ([https://en.wikipedia.org/wiki/Cipher_suite cipher suite]). This makes you vulnerable to [https://en.wikipedia.org/wiki/Man-in-the-middle_attack man-in-the-middle-attacks].

### HASH_ALGO

Your server certificate uses the weak hash algorithm :HASH. This allows the [[Certificate|certificate]] to be forged very easily. However, a weak hash algorithm will not cause a warning message to be displayed when your website is accessed.

### HTTPS_RESPONSE

The server “:HOST“ does not respond to encrypted HTTP (HTTPS) requests.

### HTTPS_SUPPORTED

The server “:HOST“ does not seem to support [https://en.wikipedia.org/wiki/Transport_Layer_Security TLS] (Transport Layer Security). This means that you are not using encryption to protect your own and your customers' data.

### NOT_YET_VALID

Your [[Certificate|certificate]] is not valid before :DATE. Until then, visitors to your website will be warned that your website may be insecure or not trustworthy.

### NULL_SUITES

Your web server/website is configured to allow unencrypted voice transmission via a secure channel. This makes you vulnerable to [https://en.wikipedia.org/wiki/Man-in-the-middle_attack man-in-the-middle-attacks].

### PORT_NO_RESPONSE

No response from server.

### RC4_SUITES

Your web server/website is configured to support the outdated [https://en.wikipedia.org/wiki/RC4 RC4] encryption method ([https://en.wikipedia.org/wiki/Cipher_suite cipher suite]), which is regarded as insecure. This makes you vulnerable to [https://en.wikipedia.org/wiki/Man-in-the-middle_attack man-in-the-middle-attacks].

### REPORT_CONSTRUCTION

An internal error occurred.

### TLS_NOT_SUPPORTED

TLS is not supported.
