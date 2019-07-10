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

import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TranslateableMessage {

    private String translationStringId;

    private List<TestInfo> placeholders;

    public TranslateableMessage(String transladtionStringId, List<TestInfo> placeholders) {
        this.translationStringId = transladtionStringId;
        this.placeholders = placeholders;
    }

    public TranslateableMessage(String translationStringId, TestInfo placeholder) {
        this.translationStringId = translationStringId;
        this.placeholders = new LinkedList<>();
        placeholders.add(placeholder);
    }

    public String getTranslationStringId() {
        return translationStringId;
    }

    public void setTranslationStringId(String translationStringId) {
        this.translationStringId = translationStringId;
    }

    public List<TestInfo> getPlaceholders() {
        return placeholders;
    }

    public void setPlaceholders(List<TestInfo> placeholders) {
        this.placeholders = placeholders;
    }
}
