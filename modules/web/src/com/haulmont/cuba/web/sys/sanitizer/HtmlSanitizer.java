/*
 * Copyright (c) 2008-2020 Haulmont.
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
 */

package com.haulmont.cuba.web.sys.sanitizer;

import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;
import org.springframework.stereotype.Component;

import javax.annotation.Nullable;
import java.util.regex.Pattern;

import static com.haulmont.cuba.gui.components.HtmlAttributes.CSS.FONT;

/**
 * Utility bean that sanitizes a sting of HTML according to the factory's policy to prevent Cross-site Scripting (XSS)
 * in HTML context.
 */
@Component(HtmlSanitizer.NAME)
public class HtmlSanitizer {

    public static final String NAME = "cuba_HtmlSanitizer";

    /**
     * Number regexp. Intended to match an attribute value that contains only numbers.
     */
    protected static final String NUMBER_REGEXP = "[+-]?(?:(?:[0-9]+(?:\\.[0-9]*)?)|\\.[0-9]+)";
    protected static final Pattern NUMBER_PATTERN = Pattern.compile(NUMBER_REGEXP);
    protected static final String SIZE_ATTRIBUTE_NAME = "size";

    /**
     * Font face regexp. Intended to match face attribute value of font element.
     */
    protected static final String FONT_FACE_REGEXP = "[\\w;, \\-]+";
    protected static final Pattern FONT_FACE_PATTERN = Pattern.compile(FONT_FACE_REGEXP);
    protected static final String FONT_FACE_ATTRIBUTE_NAME = "face";

    /**
     * Color regexp. Intended to match an attribute value that contains the value of color.
     */
    protected static final String COLOR_REGEXP = "(#(?:[0-9a-f]{2}){2,4}|(#[0-9a-f]{3})" +
            "|(rgb|hsl)a?\\((-?\\d+%?[,\\s]+){2,3}\\s*[d\\.]+%?\\)" +
            "|\\b(|aliceblue|antiquewhite|aqua|aquamarine|azure|beige|bisque|black|blanchedalmond|blue|blueviolet|brown" +
            "|burlywood|cadetblue|chartreuse|chocolate|coral|cornflowerblue|cornsilk|crimson|cyan|darkblue|darkcyan" +
            "|darkgoldenrod|darkgray|darkgreen|darkgrey|darkkhaki|darkmagenta|darkolivegreen|darkorange|darkorchid" +
            "|darkred|darksalmon|darkseagreen|darkslateblue|darkslategray|darkslategrey|darkturquoise|darkviolet" +
            "|deeppink|deepskyblue|dimgray|dimgrey|dodgerblue|firebrick|floralwhite|forestgreen|fuchsia|gainsboro" +
            "|ghostwhite|goldenrod|gold|green|greenyellow|gray|grey|honeydew|hotpink|indianred|indigo|ivory|khaki" +
            "|lavenderblush|lavender|lawngreen|lemonchiffon|lightblue|lightcoral|lightcyan|lightgoldenrodyellow" +
            "|lightgray|lightgreen|lightgrey|lightpink|lightsalmon|lightseagreen|lightskyblue|lightslategray" +
            "|lightslategrey|lightsteelblue|lightyellow|lime|limegreen|linen|magenta|maroon|mediumaquamarine|mediumblue" +
            "|mediumorchid|mediumpurple|mediumseagreen|mediumslateblue|mediumspringgreen|mediumturquoise|mediumvioletred" +
            "|midnightblue|mintcream|mistyrose|moccasin|navajowhite|navy|oldlace|olive|olivedrab|orange|orangered" +
            "|orchid|palegoldenrod|palegreen|paleturquoise|palevioletred|papayawhip|peachpuff|peru|pink|plum|powderblue" +
            "|purple|rebeccapurple|red|rosybrown|royalblue|saddlebrown|salmon|sandybrown|seagreen|seashell" +
            "|sienna|silver|skyblue|slateblue|slategray|slategrey|snow|springgreen|steelblue|tan|teal|thistle|tomato" +
            "|turquoise|violet|wheat|white|whitesmoke|yellow|yellowgreen)\\b)";
    protected static final Pattern COLOR_PATTERN = Pattern.compile(COLOR_REGEXP);
    protected static final String COLOR_ATTRIBUTE_NAME = "color";

    /**
     * A policy factory that is used to produce HTML sanitizer policies that sanitize a sting of HTML.
     */
    protected static final PolicyFactory POLICY_FACTORY = new HtmlPolicyBuilder()
            .allowCommonInlineFormattingElements()
            .allowAttributes(COLOR_ATTRIBUTE_NAME).matching(COLOR_PATTERN).onElements(FONT)
            .allowAttributes(FONT_FACE_ATTRIBUTE_NAME).matching(FONT_FACE_PATTERN).onElements(FONT)
            .allowAttributes(SIZE_ATTRIBUTE_NAME).matching(NUMBER_PATTERN).onElements(FONT)
            .toFactory()
            .and(Sanitizers.FORMATTING)
            .and(Sanitizers.LINKS)
            .and(Sanitizers.BLOCKS)
            .and(Sanitizers.IMAGES)
            .and(Sanitizers.STYLES)
            .and(Sanitizers.TABLES);

    /**
     * Sanitizes a string of HTML according to the factory's policy.
     *
     * @param html the string of HTML to sanitize
     * @return a string of HTML that complies with the factory's policy
     */
    public String sanitize(@Nullable String html) {
        return POLICY_FACTORY.sanitize(html);
    }
}
