package de.rub.nds.siwecos.tls.json;

public class ErrorTestInfo extends TestInfo {

    private String errorMessage;

    public ErrorTestInfo(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

}
