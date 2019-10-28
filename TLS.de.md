
# TLS

TLS Scanner

## BLEICHENBACHER_VULNERABLE

### Headline

Überprüfung auf Bleichenbacher Schwachstelle <span class="promarker"></span>

### Category

Attacks

### Description

Der [[Server]] ist verwundbar durch einen [[Bleichenbacher-Schwachstelle/DE|Bleichenbacher]] Angriff. Hierbei kann die Kommunikation entschlüsselt und Nutzereingaben wie Passwörter mitgelesen werden.

### Background

Die sogenannte Bleichenbacher-Attacke (auch unter dem Namen ROBOT bekannt) ist eine 19 Jahre alte [[Sicherheitslücke]], die es ermöglicht [[Verschlüsselung|RSA-Entschlüsselungs- und Signaturoperationen]] mit dem privaten Schlüssel eines [[Transport_Layer_Security|TLS-Servers]] auszuführen. Bei dem Angriff handelt es sich um einen Fehler im Programmcode.

### Consequence

Der [[Server]] ist verwundbar durch eine Schwachstelle, welche es einem Angreifer erlaubt, die Kommunikation zu entschlüsseln.

### Solution_Tips

Wenn ''Verwundbarkeit'' gemeldet wurde, spielen Sie umgehend ein Update für Ihre [[Transport Layer Security|TLS-Implementierung]] auf Ihrem [[Server]] ein.

### Link

Bleichenbacher-Schwachstelle

### Negative

Verwundbar durch [[Bleichenbacher-Schwachstelle/DE|Bleichenbacher]].

### Positive

Nicht verwundbar durch [[Bleichenbacher-Schwachstelle/DE|Bleichenbacher]].

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CERTIFICATE_EXPIRED

### Headline

Überprüfung der Zertifikat Laufzeit

### Category

Certificates

### Description

Die Meldung bedeutet, dass Ihr [[Zertifikate|Server-Zertifikat]] abgelaufen ist. Ihre Webseite wird Besuchern als unsicher bzw. nicht vertrauenswürdig angezeigt. Sollte ein Nutzer Ihre Webseite über [[HTTPS]] aufrufen, wird ihm möglicherweise eine Fehlermeldung angezeigt, z. B. "Ihr Zertifikat ist am (Datum) abgelaufen".

### Background

[[Zertifikate|Server-Zertifikate]] sorgen für mehr Sicherheit im Internet und dienen zur [[Verifizierung]] von Webseiten. Ein [[Zertifikate|Zertifikat]] wird von offiziellen, vertrauenswürdigen Institutionen ausgestellt und verifiziert die Identität der Webseite. Ein [[Zertifikate|Zertifikat]] ist nicht fälschbar. Im normalen Leben ist ein [[Zertifikate|Zertifikat]] mit dem Personalausweis bzw. einer notariellen Beglaubigung vergleichbar. Ähnlich wie ein Reisepass haben auch [[Zertifikate|Zertifikate]] eine bestimmte Gültigkeitsdauer. [[Zertifikate|Zertifikate]] sorgen somit für einen sicheren Datenaustausch und bilden eine wichtige Vertrauensgrundlage für Betreiber von z. B. Online-Shops.

### Consequence

Die meisten [[Browser|Internet-Browser]] sind so konfiguriert, dass Sie per Standard-Einstellung Webseiten mit einem abgelaufenen [[Zertifikate|Zertifikat]] nicht vertrauen. Eine Webseite mit abgelaufenen [[Zertifikate|Zertifikat]] erzeugt somit eine Warnung bei jedem Aufruf Ihrer Webseite, manche [[Browser]] oder [[Plugin|Plugins]] können je nach Einstellung sogar verhindern, dass man Ihre Webseite überhaupt aufrufen kann. Eine Warnmeldung beim Besuch Ihrer Webseite wirkt sich somit negativ auf Ihre Unternehmensdarstellung im Internet aus. Wenn schon [[Browser|Internet-Browser]] Ihrer Webseite nicht vertrauen, warum sollten es dann Ihre Kunden tun? Ein abgelaufenes [[SSL|SSL-Zertifikat]] wirkt sich auch als ein negatives Kriterium in Suchmaschinen-Rankings aus. Unter Umständen wird Ihr Unternehmen nicht mehr als erstes Ergebnis in einer Suchmaschine angezeigt und rutscht je nach Dauer des Problems immer weiter nach unten. Möglicherweise werden Besucher bereits im Suchergebnis auf ein Sicherheitsproblem auf Ihrer Webseite hingewiesen.

### Solution_Tips

Wenn ''Zertifikat abgelaufen'' gemeldet wurde, erneuern Sie das eingesetzte [[Zertifikate|Zertifikat]]. Wie Sie Zertifikate verlängern können, lesen Sie hier: [[Zertifikate#Was_tun.2C_wenn_ein_SSL-Zertifikat_abgelaufen_ist.3F|Zertifikat abgelaufen]].

### Link

Zertifikat-Abgelaufen

### Negative

[[Zertifikate|Zertifikat]] abgelaufen

### Positive

[[Zertifikate|Zertifikat]] nicht abgelaufen

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CERTIFICATE_NOT_SENT_BY_SERVER

### Headline

Überprüfung der Zertifikatsübermittlung

### Category

Certificates

### Description

Der [[Server]] hat kein [[Zertifikate|Zertifikat]] gesendet. Dies ist ungewöhnlich und sollte nicht vorkommen. Der Server sollte seine [[Transport_Layer_Security|TLS-Konfiguration]] überprüfen und ggfs. [[Schluesselaustauschverfahren/DE|anonyme Cipher Suites]] ausschalten.

### Background

Es ist theoretisch möglich einen [[Transport_Layer_Security|TLS-Server]] so zu konfigurieren, dass er kein [[Zertifikate|Zertifikat]] sendet, um sich auszuweisen und lediglich verschlüsselt ohne seinen [[Verschlüsselung|öffentlichen Schlüssel]] zu signieren. Ein [[Client]] der sich mit dem Server verbinden möchte, kann dann nicht überprüfen, ob er wirklich mit dem Server redet den er erwartet. Diese Art der Konfiguration ist äußerst selten.

### Consequence

Ohne [[Zertifikate|Zertifikat]] für Ihre Webseiten können Angreifer Ihre Kommunikation belauschen. Kriminelle könnten so anonym persönliche Daten Ihrer Kunden wie z. B. Passwörter oder auch Kreditkarten-Informationen abgreifen.

### Solution_Tips

Wenn ''Server sendet kein Zertifikat'' gemeldet wurde, aktualisieren Sie dringend die von Ihnen eingesetzte [[Transport_Layer_Security|TLS-Implementierung]]. Moderne Software erlaubt diese Art der Konfiguration nicht mehr.

### Link

Zertifikat-Nicht-Gesendet

### Negative

Server sendet kein Zertifikat

### Positive

Server sendet ein Zertifikat

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CERTIFICATE_NOT_VALID_YET

### Headline

Überprüfung der Zertifikat Gültigkeit

### Category

Certificates

### Description

Die Meldung bedeutet, dass Ihr [[Zertifikate|Server-Zertifikat]] noch nicht gültig ist. Ihre Webseite wird Besuchern als unsicher bzw. nicht vertrauenswürdig angezeigt. Sollte ein Nutzer Ihre Webseite über [[HTTPS]] aufrufen, wird ihm möglicherweise eine Fehlermeldung angezeigt.

### Background

[[Zertifikate|Server-Zertifikate]] sorgen für mehr Sicherheit im Internet und dienen zur [[Verifizierung|Verifizierung (Echtheit)]]der Identität von Webseiten. Ein [[Zertifikate|Zertifikat]] wird von offiziellen, vertrauenswürdigen Institutionen ausgestellt. Ein [[Zertifikate|Zertifikat]] ist nicht fälschbar. Im normalen Leben ist ein [[Zertifikate|Zertifikat]] mit dem Personalausweis bzw. einer notariellen Beglaubigung vergleichbar. Ähnlich wie ein Reisepass haben auch [[Zertifikate|Zertifikate]] eine bestimmte Gültigkeitsdauer. [[Zertifikate|Zertifikate]] sorgen somit für einen sicheren Datenaustausch und bilden eine wichtige Vertrauensgrundlage für Betreiber z. B. von Online-Shops.

### Consequence

Die meisten [[Browser|Internet-Browser]] sind so konfiguriert, dass sie per Standard-Einstellung Webseiten mit einem abgelaufenen [[Zertifikate|Zertifikat]] nicht vertrauen. Eine Webseite mit abgelaufenen [[Zertifikate|Zertifikat]] erzeugt somit eine Warnung bei jedem Aufruf Ihrer Webseite, manche [[Browser]] oder [[Plugin|Plugins]] können je nach Einstellung sogar verhindern, dass man Ihre Webseite überhaupt aufrufen kann.
Eine Warnmeldung beim Besuch Ihrer Webseite wirkt sich somit negativ auf Ihre Unternehmensdarstellung im Internet aus. Wenn schon Internet-Browser Ihrer Webseite nicht vertrauen, warum sollten es dann Ihre Kunden tun? Ein abgelaufenes [[SSL|SSL-Zertifikat]] wirkt sich auch als ein negatives Kriterium in Suchmaschinen-Rankings aus. Womöglich wird Ihr Unternehmen nicht mehr als erstes Ergebnis in einer Suchmaschine angezeigt und rutscht je nach Dauer des Problems immer weiter nach unten. Möglicherweise werden Besucher bereits im Suchergebnis auf ein Sicherheitsproblem auf Ihrer Webseite hingewiesen.

### Solution_Tips

Wenn ''Zertifikat noch nicht gültig'' gemeldet wurde, setzen sie Ihr altes [[Zertifikate|Zertifikat]] ein, so lange dies noch gültig ist. Wie Sie [[Zertifikate|Zertifikate]] verlängern können, lesen Sie hier: [[Zertifikat-Abgelaufen/DE|Zertifikat abgelaufen]].

### Link

Zertifikat-Nicht-Gueltig

### Negative

[[Zertifikate|Zertifikat]] noch nicht gültig

### Positive

[[Zertifikate|Zertifikat]] ist schon gültig

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CERTIFICATE_WEAK_HASH_FUNCTION

### Headline

Überprüfung der Verschlüsselungsstärke des Zertifikats

### Category

Certificates

### Description

Die Meldung bedeutet, dass Ihr [[Zertifikate|Server-Zertifikat]] einen schwachen [[Hashing|Hash-Algorithmus]] besitzt. Dadurch kann es potentiell gefälscht werden und wird in vielen Browsern als unsicher angezeigt.

### Background

[[Zertifikate|Server-Zertifikate]] sorgen für mehr Sicherheit im Internet und dienen zur [[Verifizierung]] der Identität von Webseiten. Ein [[Zertifikate|Zertifikat]] wird von offiziellen, vertrauenswürdigen Institutionen ausgestellt. Ein [[Zertifikate|Zertifikat]] ist nicht fälschbar solage ein starker Hash-Algorithmus verwendet wird. Im normalen Leben ist ein [[Zertifikate|Zertifikat]] mit dem Personalausweis bzw. einer notariellen Beglaubigung vergleichbar. Ähnlich wie ein Reisepass haben auch [[Zertifikate|Zertifikate]] eine bestimmte Gültigkeitsdauer. [[Zertifikate|Zertifikate]] sorgen somit für einen sicheren Datenaustausch und bilden eine wichtige Vertrauensgrundlage für Betreiber z. B. von Online-Shops.

### Consequence

Ein schwacher ([[Hashing|Hash-Algorithmus]]) kann im schlimmsten Fall dazu führen, dass Angreifer ein gefälschtes [[Zertifikate|Zertifikat]] für Ihre Webseiten erstellen können und somit Ihre Webseite impersonifizieren. Das bedeutet, dass sich ein Server als einen anderen Server ausgeben kann. Kriminelle könnten so persönliche Daten Ihrer Kunden wie z. B. Passwörter oder auch Kreditkarten-Informationen abgreifen.

### Solution_Tips

Wenn ''schwacher Hash-Algorithmus'' gemeldet wird, sollten Sie ein neues [[Zertifikate|Zertifikat]] mit einer sicheren [[Hashing|Hash-Funktion]] installieren. Wie Sie ein sicheres [[Zertifikate|Zertifikat]] bekommen, lesen Sie hier: [[Zertifikate#Wie_wird_ein_SSL-Zertifikat_installiert.3F|Zertifikat installieren]].

### Link

Schwache-Verschluesselung

### Negative

Schwacher [[Hashing|Hash-Algorithmus]]

### Positive

Starker [[Hashing|Hash-Algorithmus]] wird genutzt

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CIPHERSUITEORDER_ENFORCED

### Headline

Überprüfung auf verantwortungsvolle Auswahl von Verschlüsselungsalgorithmen

### Category

Cryptography

### Description

Ihr Webserver/Ihre Webseite ist so konfiguriert, dass die Verschlüsselungsalgorithmen des Webseiten-Besuchers bevorzugt wird, statt die Ihres Webservers. [[Server]] sollten die Auswahl der Verschlüsselungsalgorithmen nicht Ihren Kunden überlassen, sondern aktiv starke Verbindungen auswählen.

### Background

Gewöhnlich bestimmt Ihr Server die Verschlüsselungsalgorithmen der Verbindung, nicht anders herum. Ähnlich wie in der realen Welt haben Sie auf Ihrem Server Hausrecht - Sie bestimmen die Regeln, der Gast muss sich dran halten. Sie sollten es nicht dem Zufall überlassen, ob Ihre Verbindungen sicher sind.

### Consequence

Sie überlassen es dem Besucher Ihrer Website zu entscheiden, wie sicher sie kommunizieren.

### Solution_Tips

Wenn ''Verantwortungslose Auswahl von Verschlüsselungsalgorithmen'' gemeldet wurden, konfigurieren Sie Ihren Webserver so, dass Ihr Webserver die Verschlüsselungsalgorithmen bei der Kommunikation zwischen Ihrer Webseite und dem Webbrowser des Besuchers bestimmt.

### Link

Verschlüsselungsalgorithmen

### Negative

Verantwortungslose Auswahl von Verschlüsselungsalgorithmen

### Positive

Verantwortungsvolle Auswahl von Verschlüsselungsalgorithmen

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CIPHERSUITE_ANON

### Headline

Überprüfung auf anonymen Schlüsselaustausch

### Category

Cryptography

### Description

Ihr Webserver/Ihre Webseite ist so konfiguriert, dass Verbindungen ohne Überprüfung der Identität Ihrers Servers erlaubt sind.

### Background

Der Begriff [[Cipher Suite]] steht für eine Sammlung eingesetzter kryptografischer Methoden (Verschlüsselung von Informationen). Diese Sammlung beinhaltetet das [[Schlüsselaustauschverfahren]], das [[Digitale_Signatur|Signaturverfahren]], die Verschlüsselung und kryptografische [[Hashing|Hash-Funktionen]]. Diese Kombination von kryptografischen Einzelkomponenten stellt die sichere Verbindung bei der Kommunikation zwischen zwei Parteien, z. B. Ihrem [[Browser]] und einem Webserver/einer Webseite sicher. Im TLS-Protokoll ([[Transport Layer Security]]) legt die [[Cipher Suite]] (kryptographisches Verfahren) fest, welche Algorithmen zum Aufbau einer gesicherten Datenverbindung verwendet werden sollen und ist maßgeblich für die Sicherheit der Verbindung verantwortlich.

### Consequence

Ihr Server ist bereit sehr schwache Verbindungen aufzubauen, welche für [[Man-in-the-middle|Man-in-the-middle Attacken]] verwundbar sind. Damit lassen sich z. B. eingegebene Passwörter oder Kreditkarten-Informationen auslesen und für kriminelle Zwecke missbrauchen.

### Solution_Tips

Wenn ''Anonymer Schlüsselaustausch wird unterstützt'' gemeldet wird, deaktivieren Sie die Unterstützung des "Anonymen Schlüsselaustauschs" in der  [[Verschlüsselungsmethodik|Verschlüsselungsmethodik]].

### Link

Schluesselaustauschverfahren

### Negative

Anonymer [[Schlüsselaustauschverfahren|Schlüsselaustausch]] wird unterstützt

### Positive

Anonymer [[Schlüsselaustauschverfahren|Schlüsselaustausch]] wird nicht unterstützt

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CIPHERSUITE_DES

### Headline

Überprüfung auf DES Verschlüsselung

### Category

Cryptography

### Description

Ihr Webserver/Ihre Webseite ist so konfiguriert, dass Sie die mittlerweile als unsicher geltende Verschlüsselungsfunktion DES ([[Verschlüsselungsmethodik|Cipher Suites]]) unterstützt. Dies ermöglicht [[Man-in-the-middle]]-Attacken.

### Background

Der Begriff [[Cipher Suite]] steht für ein kryptografisches Gesamt-Protokoll, welches das [[Schlüsselaustauschverfahren]], das [[Digitale_Signatur|Signaturverfahren]], die Verschlüsselung und kryptografische [[Hashing|Hash-Funktionen]] umfasst. Diese Kombination von kryptografischen Einzelkomponenten stellt die sichere Verbindung bei der Kommunikation zwischen zwei Parteien, z. B. Ihrem Browser und einem Webserver/einer Webseite sicher. Im TLS-Protokoll ([[Transport Layer Security]]) legt die Cipher Suite fest, welche Algorithmen zum Aufbau einer gesicherten Datenverbindung verwendet werden sollen.

### Consequence

Angreifer können mit dem Einsatz der DES [[Verschlüsselung]] die Kommunikation zwischen Ihrer Webseite und dem Browser Ihres Kunden entschlüsseln, da DES keine ausreichende Sicherheit bietet. Darüber lassen sich z. B. eingegebene Passwörter, Formular-Daten oder Kreditkarten-Informationen entschlüsseln und für kriminelle Zwecke missbrauchen.

### Solution_Tips

Wenn ''Veraltete DES Verschlüsselung unterstützt'' gemeldet wurde, deaktivieren Sie die Unterstützung der DES [[Verschlüsselung|Cipher Suites]] in Ihrer Webserver-Software.

### Link

Schwache-DES-Verschlüsselung

### Negative

Veraltete DES [[Verschlüsselung]] unterstützt

### Positive

Keine veraltete DES [[Verschlüsselung]] unterstützt

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CIPHERSUITE_EXPORT

### Headline

Überprüfung auf schwache Verschlüsselungs-Funktionen

### Category

Cryptography

### Description

Ihr Webserver/Ihre Webseite ist so konfiguriert, dass sich vorsätzlich unsichere [[Verschlüsselungsmethodik|Verschlüsselungsmethoden]] nutzen lassen. Dies ermöglicht es mittels [[Man-in-the-middle|Man-in-the-middle-Attacken]]  die Kommunikation mit Ihrem Server zu entschlüsseln.

### Background

Der Begriff [[Cipher Suite]] steht für eine Sammlung eingesetzter kryptografischer Methoden. Diese Sammlung beinhaltetet das [[Schlüsselaustauschverfahren]], das [[Digitale_Signatur|Signaturverfahren]], die Verschlüsselung und kryptografische [[Hashing|Hash-Funktionen]]. Diese Kombination von kryptografischen Einzelkomponenten stellt die sichere Verbindung bei der Kommunikation zwischen zwei Parteien, z. B. Ihrem [[Browser]] und einem Webserver/einer Webseite sicher. Im TLS-Protokoll ([[Transport Layer Security]]) legt die [[Cipher Suite]] fest, welche Algorithmen zum Aufbau einer gesicherten Datenverbindung verwendet werden sollen und ist maßgeblich für die Sicherheit der Verbindung verantwortlich.

### Consequence

Angreifer können bei einer schwachen [[Verschlüsselungsmethodik|Verschlüsselungsmethodik]] die Kommunikation zwischen Ihrer Webseite und dem [[Browser]] Ihres Kunden problemlos entschlüsseln. Damit lassen sich z. B. eingegebene Passwörter, Formular-Daten oder Kreditkarten-Informationen auslesen und für kriminelle Zwecke missbrauchen.  Dies ermöglicht [[Man-in-the-middle]]-Attacken.

### Solution_Tips

Wenn ''Schwache Export Verschlüsselung unterstützt'' gemeldet wird, deaktivieren Sie die Unterstützung von EXPORT [[Verschlüsselungsmethodik|Verschlüsselungsmethoden]] im Webserver.

### Link

Geschwaechte-Verschluesselung

### Negative

Schwache [[EXPORT-Verschlüsselung|Export Verschlüsselung]] unterstützt

### Positive

Keine schwache [[EXPORT-Verschlüsselung|EXPORT Verschlüsselung]] unterstützt

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CIPHERSUITE_NULL

### Headline

Überprüfung auf NULL-Chiffren

### Category

Cryptography

### Description

Ihr Webserver/Ihre Webseite ist so konfiguriert, dass zugelassen wird, dass unverschlüsselt über einen geschützten Kanal gesprochen werden kann. Dies ermöglicht [[Man-in-the-middle|Man-in-the-middle-Attacken]].

### Background

Der Begriff [[Cipher Suite]] steht für eine Gruppe kryptografischer Funktionen, welches das [[Schlüsselaustauschverfahren]], das [[Digitale_Signatur|Signaturverfahren]], die Verschlüsselung und kryptografische [[Hashing|Hash-Funktionen]] umfasst. Diese Kombination von kryptografischen Einzelkomponenten stellt die sichere Verbindung bei der Kommunikation zwischen zwei Parteien, z. B. Ihrem [[Browser]] und einem Webserver/einer Webseite sicher. Im TLS-Protokoll ([[Transport Layer Security]]) legt die [[Cipher Suite]] fest, welche Algorithmen zum Aufbau einer gesicherten Datenverbindung verwendet werden sollen.

### Consequence

Angreifer können bei fehlender Verschüsselung die Kommunikation zwischen Ihrer Webseite und dem [[Browser]] Ihres Kunden problemlos mitlesen. Damit lassen sich z. B. eingegebene Passwörter, Formular-Daten oder Kreditkarten-Informationen auslesen und für kriminelle Zwecke missbrauchen.

### Solution_Tips

Wenn ''Unsichere NULL Chiffren unterstützt'' gemeldet wurde, deaktivieren Sie die Unterstützung von NULL [[Verschlüsselungsmethodik|Verschlüsselungsmethoden]].

### Link

Unverschluesselte-Kommunikation

### Negative

Unsichere [[NULL-Algorithmus|NULL Chiffren]] unterstützt

### Positive

Keine unsicheren [[NULL-Algorithmus|Null Chiffren]] unterstützt

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CIPHERSUITE_RC4

### Headline

Überprüfung auf RC4 Verschlüsselungsmethodik

### Category

Cryptography

### Description

Ihr Webserver/Ihre Webseite ist so konfiguriert, dass die mittlerweile als unsicher geltende Verschlüsselungsfunktion [[RC4]] weiterhin unterstützt wird. Dies schwächt Ihre Verbindungen und kann zur Entschlüsselung Ihrer Daten durch einen Angreifer führen.

### Background

Der lange sehr verbereitete Verschlüsselungsalgorithmus [[RC4|RC4]] gilt seit vielen Jahren als unsicher. Sicherheitsforschern sind viele kritische Lücken bekannt. Im Jahr 2015 hat die IETF (Internet Engineering Task Force) den Einsatz von RC4 für [[Transport Layer Security|TLS-Verbindungen]] im [https://tools.ietf.org/html/rfc7465 RFC7465] verboten.

### Consequence

Angreifer können mit dem Einsatz der [[RC4|RC4 Verschlüsselung]] die Kommunikation zwischen Ihrer Webseite und dem Browser Ihres Kunden potentiell entschlüsseln, da RC4 bekannte [[Schwachstellen|Schwachstellen]] aufweist. Darüber lassen sich z. B. eingegebene Passwörter, Formular-Daten oder Kreditkarten-Informationen auslesen und für kriminelle Zwecke missbrauchen.

### Solution_Tips

Wenn ''Veraltete RC4 Verschlüsselung unterstützt'' gemeldet wurde, deaktivieren Sie die Unterstützung der [[RC4|RC4 Verschlüsselung]].

### Link

Unsichere-RC4-Verschluesselung

### Negative

Veraltete RC4 Verschlüsselung unterstützt

### Positive

Keine veraltete [[RC4|RC4 Verschlüsselung]] unterstützt

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## CRIME_VULNERABLE

### Headline

Überprüfung auf die CRIME Schwachstelle

### Category

Attacks

### Description

Der Server ist verwundbar durch [[Crime-Schwachstelle/DE|CRIME]]. Eine Schwachstelle, welche es einem Angreifer erlaubt, die Kommunikation zu entschlüsseln.

### Background

Bei dem CRIME Angriff wird ausgenutzt, dass sich durch eine Datenkompression die Länge der verschlüsselten Nachrichten ändern kann, und dies Rückschlüsse auf den Klartext liefert. Dies kann von einem geschickten Angreifer genutzt werden, um bspw. Cookies zu stehlen.

### Consequence

Der Server ist verwundbar durch eine Schwachstelle, welche es einem Angreifer erlaubt, die Kommunikation zu entschlüsseln.

### Solution_Tips

CRIME kann verhindert werden, indem die Verwendung von Komprimierung von Daten in TLS abgeschaltet wird. Deaktivieren Sie [[Transport Layer Security|TLS-Compression]] auf Ihrem Server.

### Link

Crime-Schwachstelle

### Negative

Verwundbar durch [[Crime-Schwachstelle/DE|CRIME]]

### Positive

Nicht verwundbar durch [[Crime-Schwachstelle/DE|CRIME]]

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## EARLYCCS_VULNERABLE

### Headline

Überprüfung auf die Early-CCS Schwachstelle

### Category

Attacks

### Description

Der Server ist verwundbar durch die Early-CCS Schwachstelle. Diese Schwachstelle erlaubt es einem Angreifer unter speziellen Umständen die Kommunikation zu entschlüsseln und Nutzereingaben wie Passwörter mitzulesen.

### Background

Bei der Early-CCS Schwachstelle handelt es sich um eine Implementierungsschwachstelle in einer TLS Softwarebibliothek von 2014. Sollten Sie von dieser Schwachstelle betroffen sein, sollten Sie dringend ihre Software updaten. Die Schwachstelle ist im Verhältnis nicht schwerwiegend, aber ein klarer Indikator dafür, dass sie seit mindestens 5 Jahren ihre Software nicht upgedatet haben und deswegen auch von schwerwiegenderen Angriffen betroffen sind.

### Consequence

Der Server ist verwundbar durch eine Schwachstelle, welche es einem Angreifer in speziellen Situationen erlaubt, die Kommunikation zu entschlüsseln. Die verwendete Software ist veraltet.

### Solution_Tips

Wenn Verwundbarkeit gemeldet wurde, spielen Sie umgehend ein Update für Ihre TLS-Implementierung auf Ihrem Server ein.

### Link

Early-CCS-Schwachstelle

### Negative

Verwundbar durch Early-CCS Schwachstelle.

### Positive

Nicht verwundbar durch Early-CCS Schwachstelle.

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## HEARTBLEED_VULNERABLE

### Headline

Überprüfung auf die Heartbleed Schwachstelle <span class="promarker"></span>

### Category

Attacks

### Description

Der Server ist verwundbar durch Heartbleed. Dadurch kann ein Angreifer sensible Daten aus dem Arbeitsspeicher des Servers auslesen, wie z. B. geheime Schlüssel und Kundendaten.

### Background

Heartbleed wird als die gravierendste Sicherheitslücke aller Zeiten beschrieben und besteht bereits seit 2011. Die Sicherheitslücke klafft in einer Software namens OpenSSL, welche die Komunikation von Daten im Internet über das Sicherheitsprotokoll TLS schützen soll. Die Lücke ist in OpenSSL bereits seit mehreren Jahren geschlossen.

### Consequence

Der Server ist verwundbar durch eine Implementierungsschwachstelle, welche es einem Angreifer erlaubt, Ihren [[Server]] anzugreifen.

### Solution_Tips

Bei Verwundbarkeit spielen Sie umgehend ein Update für Ihre [[Transport Layer Security|TLS-Implementierung]] auf Ihrem [[Server]] ein.

### Link

Heartbleed-Schwachstelle

### Negative

Verwundbar durch [[Heartbleed-Schwachstelle/DE|Heartbleed]]

### Positive

Nicht verwundbar durch [[Heartbleed-Schwachstelle/DE|Heartbleed]]

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## HTTPS_NOT_SUPPORTED

### Headline

Überprüfung auf HTTPS-Unterstützung

### Category

Information

### Description

Der [[Server]] scheint kein TLS ([[Transport_Layer_Security|Transportschichtsicherheit]]) zu unterstützen. Dies bedeutet, dass Sie keinerlei Verschlüsselung einsetzen, um Ihre Daten und die Ihrer Kunden zu schützen.

### Background

Der Server “:HOST“ scheint kein TLS ([[Transport_Layer_Security|Transportschichtsicherheit]]) zu unterstützen. Dies bedeutet, dass Sie keinerlei Verschlüsselung einsetzen, um Ihre Daten und die Ihrer Kunden zu schützen.

### Consequence

Jeder kann Ihre Daten mitlesen oder Inhalte Ihrer Webseite während der Übertragung manipulieren.

### Solution_Tips

Wenn ''Server scheint kein TLS zu unterstützen'' gemeldet wird, aktivieren Sie TLS ([[Transport_Layer_Security|Transportschichtsicherheit]]).

### Link

Keine-TLS-Unterstuetzung

### Negative

Server scheint kein [[Transport_Layer_Security|TLS]] zu unterstützen.

### Positive

Server unterstützt [[Transport_Layer_Security|TLS]].

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## HTTPS_NO_RESPONSE

### Headline

Überprüfung auf HTTPS-Unterstützung

### Category

Information

### Description

Der [[Server]] scheint überhaupt nicht zu antworten. Haben sie die [[Domain]] richtig eingegeben?

### Background

Der [[Server]] scheint nicht zu antworten, wurde die [[Domain]] richtig eingegeben?

### Consequence

Die Webseite konnte nicht erreicht werden.

### Solution_Tips

Wenn der Server nicht antwortet, überprüfen Sie bitte Ihre Eingabe auf Eingabefehler.

### Link

Antwortzeit-Ueberschritten

### Negative

[[Server]] antwortet nicht.

### Positive

[[Server]] antwortet.

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## INVALID_CURVE_EPHEMERAL_VULNERABLE

### Headline

Überprüfung auf die Ephemeral Invalid Curve Schwachstelle <span class="promarker"></span>

### Category

Attacks

### Description

Der [[Server]] ist verwundbar durch einen [[Invalid-Curve-Ephemeral-Schwachstelle/DE|Ephemeral Invalid Curve Angriff]]. Dadurch kann ein Angreifer die Verbindungen angreifen.

### Background

Die Elliptic Curve Cryptography (ECC) ist aufgrund ihrer Sicherheits- und Leistungsmerkmale einer der Grundfeiler der modernen Kryptographie. Es wird in [[Schlüsselaustauschverfahren|Schlüsselaustauschprotokollen]] sowie zur Berechnung von Signaturen verwendet. Durch eine falsche Verwendung können allerdings fatale Sicherheitslücken entstehen.

### Consequence

Der [[Server]] ist verwundbar durch eine Implementierungsschwachstelle, welche es einem Angreifer erlaubt, die Kommunikation zu entschlüsseln.

### Solution_Tips

Wenn Verwundbarkeit gemeldet wurde, spielen Sie umgehend ein Update für Ihre [[Transport Layer Security|TLS-Implementierung]] auf Ihrem [[Server]] ein.

### Link

Invalid-Curve-Ephemeral-Schwachstelle

### Negative

Verwundbar durch [[Invalid-Curve-Ephemeral-Schwachstelle/DE|Ephemeral Invalid Curve Angriff]] Angriffe.

### Positive

Nicht verwundbar durch [[Invalid-Curve-Ephemeral-Schwachstelle/DE|Ephemeral Invalid Curve Angriff]] Angriffe.

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## INVALID_CURVE_VULNERABLE

### Headline

Überprüfung auf die Invalid Curve Schwachstelle <span class="promarker"></span>

### Category

Attacks

### Description

Der [[Server]] ist verwundbar durch einen Invalid Curve Angriff. Dadurch kann ein Angreifer den geheimen Schlüssel Ihres [[Zertifikate|Zertifikats]] stehlen. Danach sind alle Ihre zukünfigen Verbindungen ebenfalls gefährdet, sowie Teile Ihrer vergangenen Kommunikation.

### Background

Für kryptografische Verschlüsselung müssen elliptische Kurven sehr sorgfältig ausgewählt werden, da aus bestimmten Kurvenpunkten die Schlüssel erstellt werden, was nicht so einfach ist.

### Consequence

Der [[Server]] ist verwundbar durch eine Implementierungsschwachstelle, welche es einem Angreifer erlaubt, die Kommunikation zu entschlüsseln und den privaten Schlüssel Ihres [[Zertifikate|Zertifikats]] zu stehlen.

### Solution_Tips

Wenn Verwundbarkeite gemeldet wurde, spielen Sie umgehend ein Update für Ihre [[Transport Layer Security|TLS-Implementierung]] auf Ihrem [[Server]] ein.  Sie sollten ebenfalls ihr Zertifikat austauschen, da dieses möglicherweise schon kompromitiert wurde.

### Link

Invalid-Curve-Schwachstelle

### Negative

Verwundbar durch [[Invalid-Curve-Schwachstelle/DE|Invalid Curve Angriffe]].

### Positive

Nicht verwundbar durch [[Invalid-Curve-Schwachstelle/DE|Invalid Curve Angriffe]].

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## PADDING_ORACLE_VULNERABLE

### Headline

Überprüfung auf die Padding-Oracle Schwachstelle <span class="promarker"></span>

### Category

Attacks

### Description

Der [[Server]] ist verwundbar durch einen Padding-Oracle Angriff, welcher es einem Angreifer erlaubt, die Kommunikation zu entschlüsseln.

### Background

Der [[PADDING-ORACLE-Schwachstelle/DE|Padding-Oracle Angriff]] kann von Angreifern genutzt werden, um gesicherte Verbindungen anzugreifen. Dazu baut er eine Verbindung zu dem [[Server]] auf und sendet sehr speziell präparierte verschlüsselte Nachrichten. Diese Nachrichten sind fast richtig verschlüsselt, haben aber an entscheidenden Positionen Fehler eingebaut. Ein Server, der so eine Nachricht empfängt, muss diese Nachrichten '''immer auf die gleiche Weise ablehnen'''. Ein Angreifer wertet die gesendeten Fehlermeldungen aus und kann durch diese Informationen ggf. die Verbindung zu dem Server teilweise entschlüsseln, wodurch die Verbindung unsicher wird.

### Consequence

Der [[Server]] ist verwundbar durch eine Implementierungsschwachstelle, welche es einem Angreifer erlaubt, die Kommunikation zu entschlüsseln.

### Solution_Tips

Wenn Verwundbarkeit gemeldet wurde, spielen Sie umgehend ein Update für Ihre [[Transport_Layer_Security|TLS Implementierung]] auf Ihrem [[Server]] ein.

### Link

PADDING-ORACLE-Schwachstelle

### Negative

Verwundbar durch [[PADDING-ORACLE-Schwachstelle/DE|Padding Oracle Angriffe]].

### Positive

Nicht verwundbar durch [[PADDING-ORACLE-Schwachstelle/DE|Padding-Oracle Angriffe]].

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## POODLE_VULNERABLE

### Headline

Überprüfung auf die POODLE Schwachstelle

### Category

Attacks

### Description

Der [[Server]] ist verwundbar durch einen POODLE-Angriff, welcher es einem Angreifer potentiell erlaubt, die Kommunikation zu entschlüsseln.

### Background

[[Poodle|POODLE]] (Padding Oracle On Downgraded Legacy Encryption) ist eine schwerwiegende Sicherheitslücke in verschiedenen Internet-Protokollen, wodurch über verschlüsselte Verbindungen private Daten von [[Client|Clients]] und [[Server|Servern]] ausgelesen werden können.

### Consequence

Der [[Server]] ist verwundbar durch eine Schwachstelle, welche es einem Angreifer erlaubt, die Kommunikation zu entschlüsseln.

### Solution_Tips

Wenn Verwundbarkeit gemeldet wurde, deaktivieren Sie umgehend das veraltete Verschlüsselungsprotokoll [[SSL|SSL3]] auf Ihrem Server!

### Link

POODLE-Schwachstelle

### Negative

Verwundbar durch [[Poodle|POODLE]]

### Positive

Nicht verwundbar durch [[Poodle|POODLE]]

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## PROTOCOLVERSION_SSL2

### Headline

Überprüfung auf veraltetes SSL2 Protokoll

### Category

Cryptography

### Description

Der [[Server]] unterstützt die veraltete Protokollversion [[SSL|SSL2]], welche als höchst unsicher gilt. Sie gefährden mit dem Einsatz der Version massiv die Sicherheit des ganzen Servers und möglicherweise Ihres gesamten Unternehmensnetzwerks.

### Background

[[SSL]] (Secure Sockets Layer) steht für ein hybrides (kombiniertes) Verschlüsselungsprotokoll zur sicheren Datenübertragung im Internet und dient als Grundlage für den sicheren Aufruf über [[HTTPS]]. Die Version [[SSL|SSL2]] stammt aus dem Jahr 1994 und wird offiziell seit 2011 nicht mehr unterstützt. Der Begriff SSL wurde inzwischen durch den Begriff [[Transport Layer Security|TLS (Transport Layer Security, dt.: Transportschichtsicherheit)]] ersetzt. Die SSL2 Lücke dient z. B. als Einfallstor für einen [https://www.heise.de/security/meldung/DROWN-Angriff-SSL-Protokoll-aus-der-Steinzeit-wird-Servern-zum-Verhaengnis-3121121.html DROWN-Angriff: SSL-Protokoll aus der Steinzeit wird Servern zum Verhängnis], was Kriminellen erlaubt, den gesamten Datenverkehr Ihrer Webseite mitzulesen.

### Consequence

[[SSL|SSL2]] wird von fast allen Internet-Browsern nicht mehr unterstützt, führt aber trozdem zu fatalen Sicherheitsproblemen auf Ihrer Webseite. [[SSL|SSL2]] ist ein Urgestein des Internets und muss umgehend abgeschaltet werden. Suchmaschinen werden Ihre Webseite für den Einsatz von SSLv2 potentiell abstrafen.

### Solution_Tips

Wenn ''Veraltete Protokollversion SSL2 wird unterstützt'' gemeldet wurde: [[Transport Layer Security|TLS-Verschlüsselung]] gilt heute als Standard. Sie sollten deshalb auf den Einsatz von [[SSL|SSL2]] verzichten. Weitere Informationen finden Sie hier: [[SSL|SSL]].

### Link

Veraltete-Protokollversion-SSL2

### Negative

Veraltete Protokollversion [[SSL|SSL2]] wird unterstützt.

### Positive

Veraltete Protokollversion [[SSL|SSL2]] wird nicht unterstützt.

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## PROTOCOLVERSION_SSL3

### Headline

Überprüfung auf veraltetes SSL3 Protokoll

### Category

Cryptography

### Description

Der [[Server]] unterstützt die veraltete Protokollversion [[SSL|SSL3]], welche als höchst unsicher gilt. Sie gefährden mit dem Einsatz der Version massiv die Sicherheit der Verbindungen zu diesem Server.

### Background

[[SSL]] (Secure Sockets Layer) steht für ein hybrides Verschlüsselungsprotokoll zur sicheren Datenübertragung im Internet und dient als Grundlage für den sicheren Aufruf über [[HTTPS]]. Die Version SSL3 stammt aus dem Jahr 1995 und wird offiziell seit 2015 nicht mehr unterstützt. Der Begriff SSL wurde inzwischen durch den Begriff [[Transport Layer Security|TLS (Transport Layer Security, dt.: Transportschichtsicherheit)]] ersetzt. Die SSL3-Lücke wurde insbesondere durch [[Poodle|POODLE]] bekannt. Durch den Einsatz von SSL3 kann die Vertraulichkeit der Verbindungen nicht mehr garantiert werden.

### Consequence

Durch das serverseitige Anbieten von SSL3 erlauben Sie Angriffe auf die Verbindungen mit älteren Clients. Dadurch kann ein Angreifer potentiell Teile der Verbindung entschlüsseln und Kundendaten stehlen.

### Solution_Tips

Wenn ''Veraltete Protokollversion SSL3 wird unterstützt'' gemeldet wird: [[Transport Layer Security|TLS-Verschlüsselung]] gilt heute als Standard. Sie sollten deshalb auf den Einsatz von [[SSL|SSL3]] verzichten. Weitere Informationen finden Sie hier: [[SSL|SSL]].

### Link

Veraltete-Protokollversion-SSL3

### Negative

Veraltete Protokollversion [[SSL|SSL3]] wird unterstützt.

### Positive

Veraltete Protokollversion [[SSL|SSL3]] wird nicht unterstützt.

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## PROTOCOLVERSION_TLS13

### Headline

Überprüfung auf Einsatz des [[Transport_Layer_Security|TLS 1.3 Protokolls]]

### Category

Cryptography

### Description

Der [[Server]] unterstützt die neueste [[Transport_Layer_Security|TLS-Protokollversion 1.3]]. Diese befindet sich noch im Standardisierungsprozess. Sollten Sie nicht wissen, was dies bedeutet, können Sie die Version ausschalten, da die meisten Browser diese Version noch nicht unterstützen und TLS 1.3 sich noch in der Entwicklung befindet.

### Background

[[Transport_Layer_Security|TLS 1.3]] ist die neueste Version von TLS. Sie ist schneller und besser.

### Consequence

[[Transport_Layer_Security|TLS 1.3]] wird von keinem [[Browser|Internetbrowser]] in der Standardkonfiguration unterstützt, weswegen sie keine Kunden gewinnen/verlieren, falls Sie diese Version nicht unterstützen.

### Solution_Tips

Es besteht kein Handlungsbedarf.

### Link

Protokollversion-TLS13-Gefunden

### Negative

Modernes [[Transport_Layer_Security|TLS 1.3 Protokoll]] wird unterstützt.

### Positive

[[Transport_Layer_Security|TLS 1.3 Protokoll]] wird nicht unterstützt.

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## SWEET32_VULNERABLE

### Headline

Überprüfung auf Sweet32 Schwachstelle

### Category

Attacks

### Description

Der [[Server]] ist verwundbar durch Sweet32, welche es einem Angreifer erlaubt unter gewissen Umständen, Teile der Kommunikation zu entschlüsseln, falls über eine Verbindung große Mengen Daten transferiert werden.

### Background

Der Angriff nutzt 64-Bit Blockchiffren aus. Der Sweet32-Angriff ermöglicht es einem Angreifer, unter bestimmten Umständen kleine Teile eine Textes wiederherzustellen, wenn er mit 64-Bit-Blockchiffren (wie bspw. 3DES) verschlüsselt wurde. Der Angriff ist nicht besonders einfach durchzuführen, weswegen sich die  Bedrohung in Grenzen hält.

### Consequence

Der [[Server]] ist verwundbar durch SWEET32, was es einem Angreifer erlaubt, die Kommunikation zu entschlüsseln.

### Solution_Tips

Wo es möglich ist, sollte man am besten auf den Einsatz von Triple-DES verzichten. Deaktivieren Sie Blockchiffren mit einer Blocklänge von 64 Bit.

### Link

Sweet32-Schwachstelle

### Negative

Verwundbar durch [[Sweet32-Schwachstelle/DE/Background|Sweet32]].

### Positive

Nicht verwundbar durch [[Sweet32-Schwachstelle/DE/Background|Sweet32]].

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## TLS_POODLE_VULNERABLE

### Headline

Überprüfung auf die TLS-POODLE Schwachstelle

### Category

Attacks

### Description

Der [[Server]] ist verwundbar durch eine Variante des Poodle-Angriffs auf [[Transport Layer Security|TLS]], was es einem Angreifer erlaubt, die Kommunikation zu entschlüsseln.

### Background

Es gibt eine Variante des POODLE Angriffs, welche auch neuere TLS Versionen attakiert. Dies ist durch einen Implementierungsfehler in den TLS Servern möglich.

### Consequence

Der Server ist verwundbar durch eine Schwachstelle, welche es einem Angreifer erlaubt, die Kommunikation zu entschlüsseln.

### Solution_Tips

Wenn Verwundbarkeit gemeldet wurde, spielen Sie umgehend ein Update für Ihre [[Transport Layer Security|TLS-Implementierung]] auf Ihrem [[Server]] ein.

### Link

TLS-POODLE-Schwachstelle

### Negative

Verwundbar durch [[TLS-POODLE-Schwachstelle/DE|TLS-POODLE]].

### Positive

Nicht verwundbar durch [[TLS-POODLE-Schwachstelle/DE|TLS-POODLE]].

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

## _RESULTS

### ANON_SUITES

Ihr Webserver/Ihre Webseite ist so konfiguriert, dass eine anonyme [[Verschlüsselungsmethodik|Verschlüsselungsmethodik]] ohne [[Authentifizierung]] bei der Verbindung erfolgt. Dies ermöglicht [[Man-in-the-middle|Man-in-the-middle Attacken]].

### CERTIFICATE_WEAK_SIGN_ALGO

Überprüfung der Zertifikat Verschlüsselung

### CERTIFICATE_WEAK_SIGN_ALGO_SUCCESS

Überprüfung der Zertifikat Verschlüsselung

### DES_SUITES

Ihr Webserver/Ihre Webseite ist so konfiguriert, dass Sie die mittlerweile als unsicher geltende Verschlüsselungsfunktion DES ([[Verschlüsselungsmethodik|Cipher Suites)]] unterstützt. Dies ermöglicht [[Man-in-the-middle|Man-in-the-middle Attacken]].

### EXPIRED

Ihr [[Zertifikate|Zertifikat]] ist am :DATE abgelaufen. Ihre Webseite wird Besuchern als unsicher bzw. nicht vertrauenswürdig angezeigt.

### EXPORT_SUITES

Ihr Webserver/Ihre Webseite ist so konfiguriert, dass sich vorsätzlich geschwächte kryptographische Funktionen ([[Cipher Suite|Cipher Suites]]) nutzen lassen. Dies ermöglicht [[Man-in-the-middle|Man-in-the-middle-Attacken]].

### HASH_ALGO

Ihr Server-Zertifikat nutzt den schwachen [[Hashing|Hash-Algorithmus]] :HASH. Das [[Zertifikate|Zertifikat]] kann so sehr einfach gefälscht werden. Eine Warnung beim Aufruf Ihrer Webseite erfolgt infolge eines schwachen [[Hashing|Hash-Algorithmus]] jedoch nicht.

### HTTPS_RESPONSE

Der [[Server]] “:HOST“ antwortet nicht auf verschlüsselte HTTP ([[HTTPS]]) Anfragen.

### HTTPS_SUPPORTED

Der [[Server]] “:HOST“ scheint kein [[Transport_Layer_Security|TLS]] zu unterstützen. Dies bedeutet, dass Sie keinerlei Verschlüsselung einsetzen, um Ihre Daten und die Ihrer Kunden zu schützen.

### NOT_YET_VALID

Ihr [[Zertifikate|Zertifikat]] wird erst am :DATE gültig. Ihre Webseite wird Besuchern bis dahin als unsicher bzw. nicht vertrauenswürdig angezeigt.

### NULL_SUITES

Ihr Webserver/Ihre Webseite ist so konfiguriert, dass zugelassen wird, dass unverschlüsselt über einen eigentlich geschützten Kanal Daten übertragen werden können. Dies ermöglicht [[Man-in-the-middle|Man-in-the-middle Attacken]].

### PORT_NO_RESPONSE

Keine Antwort vom Server.

### RC4_SUITES

Ihr Webserver/Ihre Webseite ist so konfiguriert, dass die mittlerweile als unsicher geltende Verschlüsselungsfunktion [[RC4_Verschlüsselungsmethodik|RC4]] weiterhin unterstützt wird. Dies ermöglicht [[Man-in-the-middle|Man-in-the-middle Attacken]].

### REPORT_CONSTRUCTION

Es trat ein interner Fehler auf.

### TLS_NOT_SUPPORTED

TLS wird nicht unterstützt.
