/*
 * Copyright (c) 2008 Haulmont Technology Ltd. All Rights Reserved.
 * Haulmont Technology proprietary and confidential.
 * Use is subject to license terms.

 * Author: Nikolay Gorodnov
 * Created: 18.11.2009 12:59:54
 *
 * $Id$
 */
package com.haulmont.cuba.web.gui.components;

import com.haulmont.chile.core.model.MetaPropertyPath;
import com.haulmont.chile.core.model.MetaClass;
import com.haulmont.chile.core.model.Instance;
import com.haulmont.chile.core.model.Range;
import com.haulmont.cuba.core.entity.Entity;
import com.haulmont.cuba.core.global.View;
import com.haulmont.cuba.core.global.MessageProvider;
import com.haulmont.cuba.gui.components.Component;
import com.haulmont.cuba.gui.components.GroupTable;
import com.haulmont.cuba.gui.components.Table;
import com.haulmont.cuba.gui.data.*;
import com.haulmont.cuba.gui.MetadataHelper;
import com.haulmont.cuba.web.gui.data.CollectionDsWrapper;
import com.haulmont.cuba.web.gui.data.SortableCollectionDsWrapper;
import com.haulmont.cuba.web.gui.data.ItemWrapper;
import com.haulmont.cuba.web.gui.data.PropertyWrapper;
import com.haulmont.cuba.web.toolkit.data.AggregationContainer;
import com.haulmont.cuba.web.toolkit.data.GroupTableContainer;
import com.vaadin.data.Item;
import com.vaadin.terminal.Resource;

import java.util.*;

import org.dom4j.Element;
import org.apache.commons.lang.StringUtils;

public class WebGroupTable extends WebAbstractTable<com.haulmont.cuba.web.toolkit.ui.GroupTable>
        implements GroupTable, Component.Wrapper
{

    public WebGroupTable() {
        component = new com.haulmont.cuba.web.toolkit.ui.GroupTable() {
            @Override
            public Resource getItemIcon(Object itemId) {
                if (styleProvider != null) {
                    @SuppressWarnings({"unchecked"})
                    final Entity item = datasource.getItem(itemId);
                    final String resURL = styleProvider.getItemIcon(item);

                    return resURL == null ? null : WebComponentsHelper.getResource(resURL);
                } else {
                    return null;
                }
            }
        };
        initComponent(component);

        component.setGroupPropertyValueFormatter(new AggregatableGroupPropertyValueFormatter());
    }

    @Override
    public void setDatasource(CollectionDatasource datasource) {
        super.setDatasource(datasource);
        if (datasource instanceof GroupDatasource) {
            datasource.addListener(new CollectionDatasourceListener<Entity>() {
                public void collectionChanged(CollectionDatasource ds, Operation operation) {
                    //todo gorodnov: make a review of CollectionDatasourceListener invocation
                    Collection groupProperties = component.getGroupProperties();
                    component.groupBy(groupProperties.toArray());
                }

                public void itemChanged(Datasource ds, Entity prevItem, Entity item) {
                }

                public void stateChanged(Datasource ds, Datasource.State prevState, Datasource.State state) {
                }

                public void valueChanged(Entity source, String property, Object prevValue, Object value) {
                }
            });
        }
    }

    @Override
    public boolean saveSettings(Element element) {
        super.saveSettings(element);

        Element groupPropertiesElement = element.element("groupProperties");
        if (groupPropertiesElement != null) {
            element.remove(groupPropertiesElement);
        }

        groupPropertiesElement = element.addElement("groupProperties");

        final Collection<?> groupProperties = component.getGroupProperties();
        for (Object groupProperty : groupProperties) {
            final Element groupPropertyElement = groupPropertiesElement.addElement("property");
            groupPropertyElement.addAttribute("id", groupProperty.toString());
        }

        return true;
    }

    @Override
    public void applySettings(Element element) {
        super.applySettings(element);

        final Element groupPropertiesElement = element.element("groupProperties");
        if (groupPropertiesElement != null) {
            final List elements = groupPropertiesElement.elements("property");
            final List<MetaPropertyPath> properties = new ArrayList<MetaPropertyPath>(elements.size());
            for (final Object o : elements) {
                final MetaPropertyPath property = datasource.getMetaClass().getPropertyEx(
                        ((Element) o).attributeValue("id")
                );
                properties.add(property);
            }
            groupBy(properties.toArray());
        }
    }

    protected CollectionDsWrapper createContainerDatasource(CollectionDatasource datasource, Collection<MetaPropertyPath> columns) {
        return new GroupTableDsWrapper(datasource, columns);
    }

    public void groupBy(Object[] properties) {
        component.groupBy(properties);
    }

    public void expandAll() {
        component.expandAll();
    }

    public void expand(GroupInfo groupId) {
        component.expand(groupId);
    }

    public void collapseAll() {
        component.collapseAll();
    }

    public void collapse(GroupInfo groupId) {
        component.collapse(groupId);
    }

    public boolean isExpanded(GroupInfo groupId) {
        return component.isExpanded(groupId);
    }

    protected class GroupTableDsWrapper extends SortableCollectionDsWrapper
            implements GroupTableContainer,
            AggregationContainer {

        private boolean groupDatasource;
        private List<Object> aggregationProperties = null;

        //Supports items expanding
        private final Set<GroupInfo> expanded = new HashSet<GroupInfo>();

        private Set<GroupInfo> expandState;

        //Items cache
        private LinkedList<Object> cachedItemIds;
        private Object first;
        private Object last;

        public GroupTableDsWrapper(CollectionDatasource datasource) {
            super(datasource, true);
            groupDatasource = datasource instanceof GroupDatasource;
        }

        public GroupTableDsWrapper(CollectionDatasource datasource, Collection<MetaPropertyPath> properties) {
            super(datasource, properties, true);
            groupDatasource = datasource instanceof GroupDatasource;
        }

        @Override
        protected void createProperties(View view, MetaClass metaClass) {
            if (columns.isEmpty()) {
                super.createProperties(view, metaClass);
            } else {
                for (Map.Entry<MetaPropertyPath, Column> entry : columns.entrySet()) {
                    final MetaPropertyPath propertyPath = entry.getKey();
                    if (view == null || MetadataHelper.viewContainsProperty(view, propertyPath)) {
                        properties.add(propertyPath);
                    }
                }
            }
        }

        @Override
        protected ItemWrapper createItemWrapper(Object item) {
            return new ItemWrapper(item, properties) {
                @Override
                protected PropertyWrapper createPropertyWrapper(Object item, MetaPropertyPath propertyPath) {
                    return new TablePropertyWrapper(item, propertyPath);
                }
            };
        }

        public void groupBy(Object[] properties) {
            if (groupDatasource) {
                doGroup(properties);
            }
        }

        private void doGroup(Object[] properties) {
            saveState();
            ((GroupDatasource) datasource).groupBy(properties);
            restoreState();
            resetCachedItems();
        }

        private void saveState() {
            //save expanding state
            expandState = new HashSet<GroupInfo>(expanded);
        }

        private void restoreState() {
            collapseAll();
            //restore groups expanding
            if (hasGroups()) {
                for (final GroupInfo groupInfo : expandState) {
                    expand(groupInfo);
                }
            }
            expandState = null;
        }

        public Collection<?> rootGroups() {
            if (hasGroups()) {
                return ((GroupDatasource) datasource).rootGroups();
            }
            return Collections.emptyList();
        }

        public boolean hasChildren(Object id) {
            return isGroup(id) && ((GroupDatasource) datasource).hasChildren((GroupInfo) id);
        }

        public Collection<?> getChildren(Object id) {
            if (isGroup(id)) {
                return ((GroupDatasource) datasource).getChildren((GroupInfo) id);
            }
            return Collections.emptyList();
        }

        public Collection<?> getGroupItemIds(Object id) {
            if (isGroup(id)) {
                return ((GroupDatasource) datasource).getGroupItemIds((GroupInfo) id);
            }
            return Collections.emptyList();
        }

        public int getGroupItemsCount(Object id) {
            if (isGroup(id)) {
                return ((GroupDatasource) datasource).getGroupItemsCount((GroupInfo) id);
            }
            return 0;
        }

        public boolean isGroup(Object id) {
            return (id instanceof GroupInfo) && ((GroupDatasource) datasource).containsGroup((GroupInfo) id);
        }

        public Object getGroupProperty(Object id) {
            if (isGroup(id)) {
                return ((GroupDatasource) datasource).getGroupProperty((GroupInfo) id);
            }
            return null;
        }

        public Object getGroupPropertyValue(Object id) {
            if (isGroup(id)) {
                return ((GroupDatasource) datasource).getGroupPropertyValue((GroupInfo) id);
            }
            return null;
        }

        public boolean hasGroups() {
            return groupDatasource && ((GroupDatasource) datasource).hasGroups();
        }

        public Collection<?> getGroupProperties() {
            if (hasGroups()) {
                return ((GroupDatasource) datasource).getGroupProperties();
            }
            return Collections.emptyList();
        }

        public void expandAll() {
            if (hasGroups()) {
                this.expanded.clear();
                expand(rootGroups());
                resetCachedItems();
            }
        }

        private void expand(Collection groupIds) {
            for (final Object groupId : groupIds) {
                expanded.add((GroupInfo) groupId);
                if (hasChildren(groupId)) {
                    expand(getChildren(groupId));
                }
            }
        }

        public void expand(Object id) {
            if (isGroup(id)) {
                expanded.add((GroupInfo) id);
                resetCachedItems();
            }
        }

        public void collapseAll() {
            if (hasGroups()) {
                expanded.clear();
                resetCachedItems();
            }
        }

        public void collapse(Object id) {
            if (isGroup(id)) {
                expanded.remove((GroupInfo) id);
                resetCachedItems();
            }
        }

        public boolean isExpanded(Object id) {
            return isGroup(id) && expanded.contains((GroupInfo) id);
        }

        public Collection getAggregationPropertyIds() {
            if (aggregationProperties != null) {
                return Collections.unmodifiableList(aggregationProperties);
            }
            return Collections.emptyList();
        }

        public Type getContainerPropertyAggregation(Object propertyId) {
            throw new UnsupportedOperationException();
        }

        public void addContainerPropertyAggregation(Object propertyId, Type type) {
            if (aggregationProperties == null) {
                aggregationProperties = new LinkedList<Object>();
            } else if (aggregationProperties.contains(propertyId)) {
                throw new IllegalStateException("Such aggregation property is already exists");
            }
            aggregationProperties.add(propertyId);
        }

        public void removeContainerPropertyAggregation(Object propertyId) {
            if (aggregationProperties != null) {
                aggregationProperties.remove(propertyId);
                if (aggregationProperties.isEmpty()) {
                    aggregationProperties = null;
                }
            }
        }

        @SuppressWarnings("unchecked")
        public Map<Object, String> aggregate(Collection itemIds) {
            return __aggregate(this, itemIds);
        }

        @Override
        public Object firstItemId() {
            if (hasGroups()) {
                return first;
            }
            return super.firstItemId();
        }

        @Override
        public Object lastItemId() {
            if (hasGroups()) {
                return last;
            }
            return super.lastItemId();
        }

        @Override
        public Object nextItemId(Object itemId) {
            if (hasGroups()) {
                if (itemId == null) {
                    throw new NullPointerException("Item id cannot be NULL");
                }
                if (isLastId(itemId)) {
                    return null;
                }
                int index = cachedItemIds.indexOf(itemId);
                return cachedItemIds.get(index + 1);
            }
            return super.nextItemId(itemId);
        }

        @Override
        public Object prevItemId(Object itemId) {
            if (hasGroups()) {
                if (itemId == null) {
                    throw new NullPointerException("Item id cannot be NULL");
                }
                if (isFirstId(itemId)) {
                    return null;
                }
                int index = cachedItemIds.indexOf(itemId);
                return cachedItemIds.get(index - 1);
            }
            return super.prevItemId(itemId);
        }

        @Override
        public boolean isFirstId(Object itemId) {
            if (hasGroups()) {
                return itemId != null && itemId.equals(first);
            }
            return super.isFirstId(itemId);
        }

        @Override
        public boolean isLastId(Object itemId) {
            if (hasGroups()) {
                return itemId != null && itemId.equals(last);
            }
            return super.isLastId(itemId);
        }

        public Object addItemAfter(Object previousItemId) throws UnsupportedOperationException {
            throw new UnsupportedOperationException();
        }

        public Item addItemAfter(Object previousItemId, Object newItemId) throws UnsupportedOperationException {
            throw new UnsupportedOperationException();
        }

        @Override
        public Collection getItemIds() {
            if (hasGroups()) {
                if (cachedItemIds == null) {
                    final LinkedList<Object> result = new LinkedList<Object>();
                    final List<GroupInfo> roots = ((GroupDatasource) datasource).rootGroups();
                    for (final GroupInfo root : roots) {
                        result.add(root);
                        collectItemIds(root, result);
                    }
                    cachedItemIds = result;

                    first = cachedItemIds.peekFirst();
                    last = cachedItemIds.peekLast();
                }
                return cachedItemIds;
            } else {
                return super.getItemIds();
            }
        }

        private void collectItemIds(GroupInfo groupId, final List<Object> itemIds) {
            if (expanded.contains(groupId)) {
                if (((GroupDatasource) datasource).hasChildren(groupId)) {
                    final List<GroupInfo> children = ((GroupDatasource) datasource).getChildren(groupId);
                    for (final GroupInfo child : children) {
                        itemIds.add(child);
                        collectItemIds(child, itemIds);
                    }
                } else {
                    itemIds.addAll(((GroupDatasource) datasource).getGroupItemIds(groupId));
                }
            }
        }

        private void resetCachedItems() {
            cachedItemIds = null;
        }

        @Override
        public int size() {
            if (hasGroups()) {
                return getItemIds().size();
            }
            return super.size();
        }
    }

    protected class AggregatableGroupPropertyValueFormatter extends DefaultGroupPropertyValueFormatter {
        @Override
        public String format(Object groupId, Object value) {
            String formattedValue = super.format(groupId, value);
            if (!StringUtils.isEmpty(formattedValue)) {
                int count = WebGroupTable.this.component.getGroupItemsCount(groupId);
                return String.format("%s (%d)", formattedValue, count);
            } else {
                return formattedValue;
            }
        }
    }

    protected class DefaultGroupPropertyValueFormatter
            implements com.haulmont.cuba.web.toolkit.ui.GroupTable.GroupPropertyValueFormatter
    {
        public String format(Object groupId, Object value) {
            if (value == null) {
                return "";
            }
            final MetaPropertyPath propertyPath = ((GroupInfo<MetaPropertyPath>) groupId).getProperty();
            final Table.Column column = columns.get(propertyPath);
            if (column != null && column.getXmlDescriptor() != null) {
                String captionProperty = column.getXmlDescriptor().attributeValue("captionProperty");
                if (column.getFormatter() != null) {
                    return column.getFormatter().format(value);
                } else if (!StringUtils.isEmpty(captionProperty)) {
                    return propertyPath.getRange().isDatatype() ?
                            propertyPath.getRange().asDatatype().format(value) :
                            String.valueOf(((Instance) value).getValue(captionProperty));
                }
            }
            final Range range = propertyPath.getRange();
            if (range.isDatatype()) {
                return range.asDatatype().format(value);
            } else if (range.isEnum()){
                String nameKey = value.getClass().getSimpleName() + "." + value.toString();
                return MessageProvider.getMessage(value.getClass(), nameKey);
            } else {
                if (value instanceof Instance) {
                    return ((Instance) value).getInstanceName();
                } else {
                    return value.toString();
                }
            }
        }
    }
}
