/*
 * Copyright (c) 2008-2018 Haulmont.
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

package spec.cuba.web.sanitizer

import com.google.common.base.Joiner
import com.haulmont.cuba.gui.components.ContentMode
import com.haulmont.cuba.gui.components.DialogAction
import com.haulmont.cuba.web.widgets.CubaLabel
import com.vaadin.ui.Notification
import com.vaadin.ui.VerticalLayout
import spec.cuba.web.UiScreenSpec
import spec.cuba.web.sanitizer.screens.SanitizerScreen

@SuppressWarnings(["GroovyAccessibility", "GroovyAssignabilityCheck", "GroovyPointlessBoolean"])
class SanitizerTest extends UiScreenSpec {

    protected static final String UNSAFE_HTML = Joiner.on('\n').join(
            "<p onclick='alert(\"XSS via event handler\")' style='alert(\"XSS via style\")'>",
            "Test Label<script>alert(\"XSS via script\")</script>",
            "</p>",
            "<p>",
            "<a href='javascript:alert(\"XSS via link\")'>Test Link</a>",
            "</p>"
    )

    protected static final String SAFE_HTML = Joiner.on('\n').join(
            "<p>",
            "Test Label",
            "</p>",
            "<p>",
            "Test Link",
            "</p>"
    )

    def setup() {
        exportScreensPackages(['spec.cuba.web.sanitizer.screens', 'com.haulmont.cuba.web.app.main'])
    }

    def "Sanitize component html caption"() {
        showMainWindow()

        def screen = screens.create(SanitizerScreen)
        screen.show()

        when: 'Caption as html is enabled and unsafe html is set to TextField'

        screen.textField.captionAsHtml = true
        screen.textField.caption = UNSAFE_HTML

        then: 'TextField has a safe html as its caption'

        screen.textField.caption == SAFE_HTML
    }

    def "Sanitize component html description"() {
        showMainWindow()

        def screen = screens.create(SanitizerScreen)
        screen.show()

        when: 'Description as html is enabled and unsafe html is set to TextField'

        screen.textField.descriptionAsHtml = true
        screen.textField.description = UNSAFE_HTML

        then: 'TextField has a safe html as its description'

        screen.textField.description == SAFE_HTML
    }

    def "Sanitize component html context help"() {
        showMainWindow()

        def screen = screens.create(SanitizerScreen)
        screen.show()

        when: 'Context help as html is enabled and unsafe html is set to TextField'

        screen.textField.contextHelpTextHtmlEnabled = true
        screen.textField.contextHelpText = UNSAFE_HTML

        then: 'TextField has a safe html as its context help'

        screen.textField.contextHelpText == SAFE_HTML
    }

    def "Sanitize html message of MessageDialog"() {
        when: 'MessageDialog with unsafe html as message is shown'

        vaadinUi.dialogs.createMessageDialog()
                .withMessage(UNSAFE_HTML)
                .withContentMode(ContentMode.HTML)
                .show()

        then: 'MessageDialog has a safe html as its message'

        vaadinUi.windows.find { window ->
            def messageLabel = ((VerticalLayout) window.content).components.first
            ((CubaLabel) messageLabel).value == SAFE_HTML
        }
    }

    def "Sanitize html message of OptionDialog"() {
        when: 'OptionDialog with unsafe html as message is shown'

        vaadinUi.dialogs.createOptionDialog()
                .withMessage(UNSAFE_HTML)
                .withContentMode(ContentMode.HTML)
                .withActions(new DialogAction(DialogAction.Type.OK))
                .show()

        then: 'OptionDialog has a safe html as its message'

        vaadinUi.windows.find { window ->
            def messageLabel = ((VerticalLayout) window.content).components.first
            ((CubaLabel) messageLabel).value == SAFE_HTML
        }
    }

    def "Sanitize html description of Notification"() {
        when: 'Notification with unsafe html as description is shown'

        vaadinUi.notifications.create()
                .withDescription(UNSAFE_HTML)
                .withContentMode(ContentMode.HTML)
                .show()

        then: 'Notification has a safe html as its description'

        vaadinUi.getExtensions().find { extension ->
            extension instanceof Notification &&
                    ((Notification) extension).description == SAFE_HTML
        }
    }

    def "Sanitize html message of MessageDialogFacet"() {
        showMainWindow()

        def screen = screens.create(SanitizerScreen)

        when: 'MessageDialog with unsafe html as message is shown'

        screen.messageDialogFacet.message = UNSAFE_HTML
        screen.messageDialogFacet.contentMode = ContentMode.HTML
        screen.messageDialogFacet.show()

        then: 'MessageDialog has a safe html as its message'

        vaadinUi.windows.find { window ->
            def messageLabel = ((VerticalLayout) window.content).components.first
            ((CubaLabel) messageLabel).value == SAFE_HTML
        }
    }

    def "Sanitize html message of OptionDialogFacet"() {
        showMainWindow()

        def screen = screens.create(SanitizerScreen)

        when: 'OptionDialog with unsafe html as message is shown'

        screen.optionDialogFacet.message = UNSAFE_HTML
        screen.optionDialogFacet.contentMode = ContentMode.HTML
        screen.optionDialogFacet.show()

        then: 'OptionDialog has a safe html as its message'

        vaadinUi.windows.find { window ->
            def messageLabel = ((VerticalLayout) window.content).components.first
            ((CubaLabel) messageLabel).value == SAFE_HTML
        }
    }

    def "Sanitize html description of NotificationFacet"() {
        showMainWindow()

        def screen = screens.create(SanitizerScreen)

        when: 'Notification with unsafe html as description is shown'

        screen.notificationFacet.description = UNSAFE_HTML
        screen.notificationFacet.contentMode = ContentMode.HTML
        screen.notificationFacet.show()

        then: 'Notification has a safe html as its description'

        vaadinUi.getExtensions().find { extension ->
            extension instanceof Notification &&
                    ((Notification) extension).description == SAFE_HTML
        }
    }
}
