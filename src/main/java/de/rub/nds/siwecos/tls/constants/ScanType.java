/**
 *  SIWECOS-TLS-Scanner - A Webservice for the TLS-Scanner Module of TLS-Attacker
 *
 *  Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 */
/*
 */
package de.rub.nds.siwecos.tls.constants;

/**
 *
 * @author robert
 */
public enum ScanType {
    TLS,
    SMTP_TLS,
    SMTPS_TLS,
    POP3_TLS,
    POP3S_TLS,
    IMAP_TLS,
    IMAPS_TLS,
    MAIL; // Scans all mail services at the same time
}
