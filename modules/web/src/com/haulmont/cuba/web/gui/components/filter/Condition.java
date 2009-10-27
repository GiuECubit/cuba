/*
 * Copyright (c) 2009 Haulmont Technology Ltd. All Rights Reserved.
 * Haulmont Technology proprietary and confidential.
 * Use is subject to license terms.

 * Author: Konstantin Krivopustov
 * Created: 15.10.2009 14:48:39
 *
 * $Id$
 */
package com.haulmont.cuba.web.gui.components.filter;

import com.haulmont.bali.util.Dom4j;
import com.haulmont.bali.util.ReflectionHelper;
import org.dom4j.Element;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.ObjectUtils;
import org.apache.commons.lang.RandomStringUtils;
import static org.apache.commons.lang.StringUtils.isBlank;

import java.util.List;
import java.util.ArrayList;

public abstract class Condition {

    public interface Listener {
        void captionChanged();
        void paramChanged();
    }

    protected String name;
    protected String caption;
    protected String locCaption;
    protected String filterComponentName;
    protected String text;
    protected boolean unary;
    protected Class javaClass;
    protected Param param;
    protected String entityAlias;

    protected List<Listener> listeners = new ArrayList<Listener>();

    protected Condition() {
        throw new UnsupportedOperationException();
    }

    protected Condition(Element element, String filterComponentName) {
        this.filterComponentName = filterComponentName;
        name = element.attributeValue("name");
        text = StringEscapeUtils.unescapeXml(element.getText());
        caption = element.attributeValue("caption");
        unary = Boolean.valueOf(element.attributeValue("unary"));

        String aclass = element.attributeValue("class");
        if (!isBlank(aclass))
            javaClass = ReflectionHelper.getClass(aclass);

        List<Element> paramElements = Dom4j.elements(element, "param");
        if (!paramElements.isEmpty()) {
            Element paramElem = paramElements.iterator().next();
            String paramName = paramElem.attributeValue("name");

            if (unary) {
                param = new Param(paramName, null);
            } else {
                aclass = paramElem.attributeValue("class");
                if (isBlank(aclass)) {
                    param = new Param(paramName, javaClass);
                } else {
                    param = new Param(paramName,
                            ReflectionHelper.getClass(paramElem.attributeValue("class")));
                }
            }

            param.parseValue(paramElem.getText());
        }
    }

    protected Condition(ConditionDescriptor descriptor) {
        name = descriptor.getName();
        caption = descriptor.getCaption();
        locCaption = descriptor.getLocCaption();
        filterComponentName = descriptor.getFilterComponentName();
        javaClass = descriptor.getJavaClass();
        param = descriptor.createParam(this);
    }

    public void addListener(Listener listener) {
        listeners.add(listener);
    }

    public void removeListener(Listener listener) {
        listeners.remove(listener);
    }

    public String getName() {
        return name;
    }

    public String getCaption() {
        return caption;
    }

    public String getLocCaption() {
        return locCaption;
    }

    public void setLocCaption(String locCaption) {
        if (ObjectUtils.equals(this.locCaption, locCaption))
            return;

        this.locCaption = locCaption;
        for (Listener listener : listeners) {
            listener.captionChanged();
        }
    }

    public String getText() {
        updateText();
        return text;
    }

    protected void updateText() {
    }

    public Param getParam() {
        return param;
    }

    public void setParam(Param param) {
        this.param = param;

        for (Condition.Listener listener : listeners) {
            listener.paramChanged();
        }
    }

    public String getEntityAlias() {
        return entityAlias;
    }

    public String getFilterComponentName() {
        return filterComponentName;
    }

    public void toXml(Element element) {
        element.setText(getText());
        element.addAttribute("name", name);
        if (javaClass != null)
            element.addAttribute("class", javaClass.getName());

        if (caption != null)
            element.addAttribute("caption", caption);

        if (unary)
            element.addAttribute("unary", "true");

        if (param != null) {
            Element paramElem = element.addElement("param");
            paramElem.addAttribute("name", param.getName());

            paramElem.setText(param.formatValue());
        }
    }

    public String getError() {
        return null;
    }

    public Class getJavaClass() {
        return javaClass;
    }

    public void setJavaClass(Class javaClass) {
        this.javaClass = javaClass;
    }

    public boolean isUnary() {
        return unary;
    }

    public void setUnary(boolean unary) {
        this.unary = unary;
    }

    public String getOperationCaption() {
        return "";
    }

    public String createParamName() {
        return "component$" + getFilterComponentName() + "." +
                getName().replace('.', '_') + RandomStringUtils.randomNumeric(5);
    }

    public abstract OperationEditor createOperationEditor();
}
