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
package de.rub.nds.siwecos.tls;

import de.rub.nds.siwecos.tls.constants.ScanType;
import de.rub.nds.siwecos.tls.json.ScanResult;
import de.rub.nds.tlsattacker.attacks.constants.DrownVulnerabilityType;
import de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsscanner.constants.CheckPatternType;
import de.rub.nds.tlsscanner.constants.GcmPattern;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.probe.mac.ByteCheckStatus;
import de.rub.nds.tlsscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.probe.padding.IdentifierResponse;
import de.rub.nds.tlsscanner.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.probe.padding.PaddingOracleStrength;
import de.rub.nds.tlsscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.report.PerformanceData;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.bleichenbacher.BleichenbacherTestResult;
import de.rub.nds.tlsscanner.report.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleCipherSuiteFingerprint;
import de.rub.nds.tlsscanner.report.result.statistics.RandomEvaluationResult;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.crypto.tls.Certificate;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author robert
 */
public class TlsScannerCallbackTest {

    public TlsScannerCallbackTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of reportToScanResult method, of class TlsScannerCallback.
     */
    @Test
    public void testReportToScanResult() {
        System.out.println("reportToScanResult");
        List<ProbeType> probeList = new LinkedList<>();
        for (ProbeType type : ProbeType.values()) {
            probeList.add(type);
        }
        SiteReport report = new SiteReport("somehost.de", probeList, false);

        report.setServerIsAlive(Boolean.TRUE);
        report.setSpeaksHttps(Boolean.TRUE);
        report.setSupportsSslTls(Boolean.TRUE);

        report.setAlpnIntolerance(Boolean.TRUE);
        report.setBleichenbacherTestResultList(new LinkedList<BleichenbacherTestResult>());
        report.setBleichenbacherVulnerable(Boolean.TRUE);
        report.setBreachVulnerable(true);
        report.setCertificate(Certificate.EMPTY_CHAIN);
        report.setCertificateExpired(true);
        report.setCertificateHasWeakHashAlgorithm(true);
        report.setCertificateHasWeakSignAlgorithm(true);
        report.setCertificateIsTrusted(true);
        report.setCertificateKeyIsBlacklisted(true);
        report.setCertificateMachtesDomainName(true);
        report.setCertificateNotYetValid(true);
        report.setCertificateChain(new CertificateChain(Certificate.EMPTY_CHAIN, "somehost.de"));
        report.setCipherSuiteIntolerance(Boolean.TRUE);
        report.setCipherSuiteLengthIntolerance512(Boolean.TRUE);
        HashSet<CipherSuite> cipherSuiteSet = new HashSet<>();
        for (CipherSuite suite : CipherSuite.values()) {
            cipherSuiteSet.add(suite);
        }
        report.setCipherSuites(cipherSuiteSet);
        report.setClientHelloLengthIntolerance(Boolean.TRUE);
        report.setCompressionIntolerance(true);
        report.setCrimeVulnerable(true);
        report.setCve20162107Vulnerable(true);
        report.setDhPubkeyReuse(true);
        report.setDrownVulnerable(DrownVulnerabilityType.FULL);
        report.setEarlyCcsVulnerable(EarlyCcsVulnerabilityType.VULN_EXPLOITABLE);
        report.setEcPubkeyReuse(Boolean.TRUE);
        report.setEmptyLastExtensionIntolerance(true);
        report.setEnforcesCipherSuiteOrdering(false);
        report.setExtensionIntolerance(Boolean.TRUE);
        report.setExtractedValueContainerList(new LinkedList<ExtractedValueContainer>());
        report.setFreakVulnerable(true);
        report.setGcmCheck(false);
        report.setGcmPattern(GcmPattern.REPEATING);
        report.setGcmReuse(Boolean.TRUE);
        report.setHeaderList(new LinkedList<HttpsHeader>());
        report.setHeartbleedVulnerable(Boolean.TRUE);
        report.setHpkpMaxAge(15);
        report.setHstsMaxAge(16l);
        report.setIgnoresCipherSuiteOffering(true);
        report.setIgnoresOfferedNamedGroups(Boolean.TRUE);
        report.setIgnoresOfferedSignatureAndHashAlgorithms(Boolean.TRUE);
        report.setInvalidCurveEphermaralVulnerable(Boolean.TRUE);
        report.setInvalidCurveVulnerable(true);
        report.setKnownVulnerability(new KnownPaddingOracleVulnerability("cve", "name", "longname",
                PaddingOracleStrength.STRONG, true, new LinkedList<CipherSuite>(), new LinkedList<CipherSuite>(), "",
                new LinkedList<String>(), new LinkedList<IdentifierResponse>(), true));
        report.setLogjamVulnerable(true);
        report.setMacCheckPatterAppData(new CheckPattern(CheckPatternType.NONE, true, new ByteCheckStatus[1]));
        report.setMacCheckPatternFinished(new CheckPattern(CheckPatternType.NONE, true, new ByteCheckStatus[1]));
        report.setMaxLengthClientHelloIntolerant(true);
        report.setNamedGroupIntolerant(Boolean.TRUE);
        report.setNamedSignatureAndHashAlgorithmIntolerance(Boolean.TRUE);
        report.setNormalHpkpPins(new LinkedList<HpkpPin>());
        report.setOnlySecondCiphersuiteByteEvaluated(true);
        report.setPaddingOracleShakyEvalResultList(new LinkedList<PaddingOracleCipherSuiteFingerprint>());
        report.setPaddingOracleTestResultList(new LinkedList<PaddingOracleCipherSuiteFingerprint>());
        report.setPaddingOracleVulnerable(Boolean.TRUE);
        report.setPerformanceList(new LinkedList<PerformanceData>());
        report.setPoodleVulnerable(true);
        report.setPrefersPfsCiphers(Boolean.FALSE);
        report.setRandomEvaluationResult(RandomEvaluationResult.NOT_RANDOM);
        report.setReflectsCipherSuiteOffering(true);
        report.setReportOnlyHpkpPins(new LinkedList<HpkpPin>());
        report.setRequiresSni(true);

        report.setSessionTicketGetsRotated(false);
        report.setSessionTicketLengthHint(1l);

        report.setSupportedCompressionMethods(new LinkedList<CompressionMethod>());
        report.setSupportedExtensions(new LinkedList<ExtensionType>());
        report.setSupportedNamedGroups(new LinkedList<NamedGroup>());
        report.setSupportedSignatureAndHashAlgorithms(new LinkedList());
        List<CipherSuite> tls13CipherSuiteList = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.values()) {
            tls13CipherSuiteList.add(suite);
        }
        report.setSupportedTls13CipherSuites(tls13CipherSuiteList);
        report.setSupportedTls13Groups(new LinkedList<NamedGroup>());
        report.setSupportedTokenBindingKeyParameters(new LinkedList<TokenBindingKeyParameters>());
        report.setSupportedTokenBindingVersion(new LinkedList<TokenBindingVersion>());
        report.setSupportsAeadCiphers(false);
        report.setSupportsAes(false);
        report.setSupportsAnonCiphers(true);
        report.setSupportsAria(false);
        report.setSupportsBlockCiphers(true);
        report.setSupportsCamellia(false);
        report.setSupportsChacha(false);
        report.setSupportsClientSideInsecureRenegotiation(true);
        report.setSupportsClientSideSecureRenegotiation(false);
        report.setSupportsDesCiphers(true);
        report.setSupportsDh(true);
        report.setSupportsExportCiphers(true);
        report.setSupportsNullCiphers(Boolean.TRUE);
        report.setSupportsRc4Ciphers(true);
        report.setSupportsRc2Ciphers(true);
        report.setSweet32Vulnerable(Boolean.TRUE);
        report.setSupportsSsl2(true);
        report.setSupportsSsl3(true);
        report.setSupportsTls13(true);
        report.setTlsPoodleVulnerable(Boolean.TRUE);
        ScanType type = null;
        TlsScannerCallback instance = new TlsScannerCallback(null, null, null);
        ScanResult reportToScanResult = instance.reportToScanResult(report, ScanType.TLS);
        System.out.println(instance.scanResultToJson(reportToScanResult));
    }

}
