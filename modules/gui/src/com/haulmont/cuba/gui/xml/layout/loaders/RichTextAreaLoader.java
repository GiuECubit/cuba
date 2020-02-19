/*
 * Copyright (c) 2008-2016 Haulmont.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.haulmont.cuba.gui.xml.layout.loaders;

import com.haulmont.cuba.gui.components.RichTextArea;
import org.apache.commons.lang3.StringUtils;
import org.dom4j.Element;

public class RichTextAreaLoader extends AbstractTextFieldLoader<RichTextArea> {
    @Override
    public void createComponent() {
        resultComponent = factory.create(RichTextArea.NAME);
        loadId(resultComponent, element);
        loadSanitizerEnabled(resultComponent, element);
    }

    protected void loadSanitizerEnabled(RichTextArea resultComponent, Element element) {
        String sanitizerEnabled = element.attributeValue("sanitizerEnabled");
        if (StringUtils.isNotEmpty(sanitizerEnabled)) {
            resultComponent.setSanitizerEnabled(Boolean.parseBoolean(sanitizerEnabled));
        }
    }
}