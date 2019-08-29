/**
 *  SIWECOS-TLS-Scanner - A Webservice for the TLS-Scanner Module of TLS-Attacker
 *
 *  Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 */
package de.rub.nds.siwecos.tls.json;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import de.rub.nds.siwecos.tls.ws.DebugOutput;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CollectedScanResult {

    private String name;

    private String version;
    private boolean hasError;

    private TranslateableMessage errorMessage;

    private int score;

    private List<ScanResult> scans;

    @JsonInclude(Include.NON_EMPTY)
    private DebugOutput debugOutput;

    public CollectedScanResult(String name, boolean hasError, TranslateableMessage errorMessage, int score,
            List<ScanResult> scans) {
        this.name = name;
        this.version = "3.0.0";
        this.hasError = hasError;
        this.errorMessage = errorMessage;
        this.score = score;
        this.scans = scans;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public DebugOutput getDebugOutput() {
        return debugOutput;
    }

    public void setDebugOutput(DebugOutput debugOutput) {
        this.debugOutput = debugOutput;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isHasError() {
        return hasError;
    }

    public void setHasError(boolean hasError) {
        this.hasError = hasError;
    }

    public TranslateableMessage getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(TranslateableMessage errorMessage) {
        this.errorMessage = errorMessage;
    }

    public int getScore() {
        return score;
    }

    public void setScore(int score) {
        this.score = score;
    }

    public List<ScanResult> getScans() {
        return scans;
    }

    public void setScans(List<ScanResult> scans) {
        this.scans = scans;
    }
}
