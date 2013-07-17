/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Endi Sukma Dewata <edewata@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2010-2011 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

define([
        'dojo/_base/declare',
        'dojo/_base/lang',
        'dojo/dom-construct',
        'dojo/on',
        'dojo/Stateful',
        'dojo/Evented',
        './_base/Singleton_registry',
        './builder',
        './ipa',
        './jquery',
        './navigation',
        './phases',
        './reg',
        './spec_util',
        './text',
        './dialog',
        './field',
        './widget'
       ], function(declare, lang, construct, on, Stateful, Evented,
                   Singleton_registry, builder, IPA, $, navigation, phases, reg, su, text) {

/**
 * Facet represents the content of currently displayed page.
 *
 * = Show, Clear, Refresh mechanism =
 *
 * Use cases:
 *   a) Display facet with defined arguments.
 *   b) Switch to facet
 *   c) Update facet state
 *
 * == Display facet by route ==
 * 1) somebody sets route
 * 2) Route is evaluated, arguments extracted.
 * 3) Facet state is updated `set_state(args, pkeys)`.(saves previous state)
 * 4) Facet show() is called
 *
 * == Display facet with defined arguments ==
 * 1) Somebody calls navigation.show(xxx);
 * 2) Facet state is updated `set_state(args, pkeys)`.(saves previous state)
 * 3) Route is updated, but the hash change is ignored
 * 4) Facet show() is called.
 *      5.1) First time show
 *          a) creates DOM
 *          b) display DOM
 *          c) refresh();
 *      5.2) Next time
 *          a) display DOM
 *          b) needs_update()? (compares previous state with current)
 *               true:
 *                  1) clear() - each facet can override to supress clear or
 *                               control the behaviour
 *                  2) refresh()
 *
 * == Swith to facet ==
 * Same as display facet but only without arguments. Arguments are extracted at
 * step 2.
 *
 * ==  Update facet state ==
 * 1) set_state(args, pkeys?)
 * 2) needs_update()?
 *      true:
 *        a) clear()
 *        b) refresh()
 * 2) Update route, ignore hash change event
 *
 * == Updating hash ==
 * Hash updates are responsibility of navigation component and application
 * controller. Application controller should listen to facet's `state_change`
 * event. And call something like navigation.update_hash(facet).
 *
 * navigation.update_hash should find all the necessary state properties (args,
 * pkeys).
 *
 * == needs_update method ==
 *
 *
 */

var exp = {};
exp.facet_spec = {};

exp.facet = IPA.facet = function(spec, no_init) {

    spec = spec || {};

    var that = new Evented();

    that.entity = IPA.get_entity(spec.entity);

    that.name = spec.name;
    that.label = text.get(spec.label);
    that.title = text.get(spec.title || that.label);
    that.tab_label = text.get(spec.tab_label || that.label);
    that.display_class = spec.display_class;
    that.no_update = spec.no_update;

    that.disable_breadcrumb = spec.disable_breadcrumb;
    that.disable_facet_tabs = spec.disable_facet_tabs;

    that.action_state = builder.build('', spec.state || {}, {}, { $factory: exp.state });
    that.actions = builder.build('', { actions: spec.actions }, {}, { $factory: exp.action_holder } );

    that.header_actions = spec.header_actions;
    that.header = spec.header || IPA.facet_header({ facet: that });

    that._needs_update = spec.needs_update;
    that.expired_flag = true;
    that.last_updated = null;
    that.expire_timeout = spec.expire_timeout || 600; //[seconds]
    that.on_update = IPA.observer();
    that.post_load = IPA.observer();

    that.dialogs = $.ordered_map();

    /**
     * domNode of container
     * Suppose to contain domNode of this and other facets.
     */
    that.container_node = spec.container_node;

    /**
     * FIXME: that.container should be eliminated
     * now it's the same as domNode
     */
    //that.container

    /**
     * domNode which contains all content of a facet.
     * Should contain error content and content. When error is moved to
     * standalone facet it will replace functionality of content.
     */
    that.domNode = null;

    // facet group name
    that.facet_group = spec.facet_group;

    that.redirect_info = spec.redirect_info;

    /**
     * Public state
     *
     */
    that.state = new FacetState();

    that.set_pkeys = function(pkeys) {

        pkeys = that.get_pkeys(pkeys);
        that.state.set('pkeys', pkeys);
    };

    /**
     * Return THE pkey of this facet. Basically the last one of pkeys list.
     *
     * @type String
     */
    that.get_pkey = function() {
        var pkeys = that.get_pkeys();
        if (pkeys.length) {
            return pkeys[pkeys.length-1];
        }
        return '';
    };

    /**
     * Gets copy of pkeys list.
     * It automatically adds empty pkeys ('') for each containing entity if not
     * specified.
     *
     * One can get merge current pkeys with supplied if `pkeys` param is
     * specified.
     *
     * @param String[] new pkeys to merge
     */
    that.get_pkeys = function(pkeys) {
        var new_keys = [];
        var cur_keys = that.state.get('pkeys') || [];
        var current_entity = that.entity;
        pkeys = pkeys || [];
        var arg_l = pkeys.length;
        var cur_l = cur_keys.length;
        var tot_c = 0;
        while (current_entity) {
            if (current_entity.defines_key) tot_c++;
            current_entity = current_entity.get_containing_entity();
        }

        if (tot_c < arg_l || tot_c < cur_l) throw {
            error: 'Invalid pkeys count. Supplied more than expected.'
        };

        var arg_off = tot_c - arg_l;
        var cur_off = cur_l - tot_c;

        for (var i=0; i<tot_c; i++) {
            // first try to use supplied
            if (tot_c - arg_l - i <= 0) new_keys[i] = pkeys[i-arg_off];
            // then current
            else if (tot_c - cur_l - i <= 0) new_keys[i] = cur_keys[i-cur_off];
            // then empty
            else new_keys[i] = '';
        }

        return new_keys;
    };

    that.get_pkey_prefix = function() {
        var pkeys = that.get_pkeys();
        if (pkeys.length > 0) pkeys.pop();

        return pkeys;
    };

    that.state_diff = function(a, b) {
        var diff = false;
        var checked = {};

        var check_diff = function(a, b, skip) {

            var same = true;
            skip = skip || {};

            for (var key in a) {
                if (a.hasOwnProperty(key) && !(key in skip)) {
                    var va = a[key];
                    var vb = b[key];
                    if (lang.isArray(va)) {
                        if (IPA.array_diff(va,vb)) {
                            same = false;
                            skip[a] = true;
                            break;
                        }
                    } else {
                        if (va != vb) {
                            same = false;
                            skip[a] = true;
                            break;
                        }
                    }
                }
            }
            return !same;
        };

        diff = check_diff(a,b, checked);
        diff = diff || check_diff(b,a, checked);
        return diff;
    };

    that.reset_state = function(state) {

        if (state.pkeys) {
            state.pkeys = that.get_pkeys(state.pkeys);
        }
        that.state.reset(state);
    };

    that.get_state = function() {
        return that.state.clone();
    };

    /**
     * Merges state into current and notifies it.
     */
    that.set_state = function(state) {

        if (state.pkeys) {
            state.pkeys = that.get_pkeys(state.pkeys);
        }
        that.state.set(state);
    };

    that.on_state_set = function(old_state, state) {
        that._on_state_change(state);
    };


    that._on_state_change = function(state) {

        // basically a show method without displaying the facet
        // TODO: change to something fine grained

        that._notify_state_change(state);

        var needs_update = that.needs_update(state);
        that.old_state = state;

        // we don't have to reflect any changes if facet dom is not yet created
        if (!that.domNode) {
            if (needs_update) that.set_expired_flag();
            return;
        }

        if (needs_update) {
            that.clear();
        }

        that.show_content();
        that.header.select_tab();

        if (needs_update) {
            that.refresh();
        }
    };

    that._notify_state_change =  function(state) {
        that.emit('facet-state-change', {
            facet: that,
            state: state
        });
    };

    that.get_dialog = function(name) {
        return that.dialogs.get(name);
    };

    that.dialog = function(dialog) {
        that.dialogs.put(dialog.name, dialog);
        return that;
    };

    that.create = function() {

        var entity_name = !!that.entity ? that.entity.name : '';

        if (that.domNode) {
            that.domNode.empty();
            that.domNode.detach();
        } else {
            that.domNode = $('<div/>', {
                'class': 'facet active-facet',
                name: that.name,
                'data-name': that.name,
                'data-entity': entity_name
            });
        }

        var domNode = that.domNode;
        that.container = domNode;

        if (!that.container_node) throw {
            error: 'Can\'t create facet. No container node defined.'
        };
        var node = domNode[0];
        construct.place(node,that.container_node);


        if (that.disable_facet_tabs) domNode.addClass('no-facet-tabs');
        domNode.addClass(that.display_class);

        that.header_container = $('<div/>', {
            'class': 'facet-header'
        }).appendTo(domNode);
        that.create_header(that.header_container);

        that.content = $('<div/>', {
            'class': 'facet-content'
        }).appendTo(domNode);

        that.error_container = $('<div/>', {
            'class': 'facet-content facet-error'
        }).appendTo(domNode);

        that.create_content(that.content);
        domNode.removeClass('active-facet');
    };

    that.create_header = function(container) {

        that.header.create(container);

        that.controls = $('<div/>', {
            'class': 'facet-controls'
        }).appendTo(container);
    };

    that.create_content = function(container) {
    };

    that.create_control_buttons = function(container) {

        if (that.control_buttons) {
            that.control_buttons.create(container);
        }
    };

    that.set_title = function(container, title) {
        var element = $('h1', that.title_container);
        element.html(title);
    };

    that.show = function() {

        that.entity.facet = that; // FIXME: remove

        if (!that.domNode) {
            that.create();

            var state = that.state.clone();
            var needs_update = that.needs_update(state);
            that.old_state = state;

            if (needs_update) {
                that.clear();
            }

            that.domNode.addClass('active-facet');
            that.show_content();
            that.header.select_tab();

            if (needs_update) {
                that.refresh();
            }
        } else {
            that.domNode.addClass('active-facet');
            that.show_content();
            that.header.select_tab();
        }
    };

    that.show_content = function() {
        that.content.css('display', 'block');
        that.error_container.css('display', 'none');
    };

    that.show_error = function() {
        that.content.css('display', 'none');
        that.error_container.css('display', 'block');
    };

    that.error_displayed = function() {
        return that.error_container &&
                    that.error_container.css('display') === 'block';
    };

    that.hide = function() {
        that.domNode.removeClass('active-facet');
    };

    that.load = function(data) {
        that.data = data;
        that.header.load(data);
    };

    that.refresh = function() {
    };

    that.clear = function() {
    };

    that.needs_update = function(new_state) {

        if (that._needs_update !== undefined) return that._needs_update;

        new_state = new_state || that.state.clone();
        var needs_update = false;

        if (that.expire_timeout && that.expire_timeout > 0) {

            if (!that.last_updated) {
                needs_update = true;
            } else {
                var now = Date.now();
                needs_update = (now - that.last_updated) > that.expire_timeout * 1000;
            }
        }

        needs_update = needs_update || that.expired_flag;
        needs_update = needs_update || that.error_displayed();

        needs_update = needs_update || that.state_diff(that.old_state || {}, new_state);

        return needs_update;
    };

    that.set_expired_flag = function() {
        that.expired_flag = true;
    };

    that.clear_expired_flag = function() {
        that.expired_flag = false;
        that.last_updated = Date.now();
    };

    that.is_dirty = function() {
        return false;
    };

    /**
     * Wheater we can switch to different facet.
     * @returns Boolean
     */
    that.can_leave = function() {
        return !that.is_dirty();
    };

    /**
     * Show dialog displaying a message explaining why we can't switch facet.
     * User can supply callback which is called when a leave is permitted.
     *
     * Listeneres should set 'callback' property to listen state evaluation.
     */
    that.show_leave_dialog = function(permit_callback) {

        var dialog = IPA.dirty_dialog({
            facet: that
        });

        dialog.callback = permit_callback;

        return dialog;
    };

    that.report_error = function(error_thrown) {

        var add_option = function(ul, text, handler) {

            var li = $('<li/>').appendTo(ul);
            $('<a />', {
                href: '#',
                text: text,
                click: function() {
                    handler();
                    return false;
                }
            }).appendTo(li);
        };

        var title = text.get('@i18n:error_report.title');
        title = title.replace('${error}', error_thrown.name);

        that.error_container.empty();
        that.error_container.append('<h1>'+title+'</h1>');

        var details = $('<div/>', {
            'class': 'error-details'
        }).appendTo(that.error_container);
        details.append('<p>'+error_thrown.message+'</p>');

        $('<div/>', {
            text: text.get('@i18n:error_report.options')
        }).appendTo(that.error_container);

        var options_list = $('<ul/>').appendTo(that.error_container);

        add_option(
            options_list,
            text.get('@i18n:error_report.refresh'),
            function() {
                that.refresh();
            }
        );

        add_option(
            options_list,
            text.get('@i18n:error_report.main_page'),
            function() {
                navigation.show_default();
            }
        );

        add_option(
            options_list,
            text.get('@i18n:error_report.reload'),
            function() {
                window.location.reload(false);
            }
        );

        that.error_container.append('<p>'+text.get('@i18n:error_report.problem_persists')+'</p>');

        that.show_error();
    };

    that.get_redirect_facet = function() {

        var entity = that.entity;
        while (entity.containing_entity) {
            entity = entity.get_containing_entity();
        }
        var facet_name = that.entity.redirect_facet;
        var entity_name = entity.name;
        var facet;

        if (that.redirect_info) {
            entity_name = that.redirect_info.entity || entity_name;
            facet_name = that.redirect_info.facet || facet_name;
        }

        if (!facet) {
            entity = IPA.get_entity(entity_name);
            facet = entity.get_facet(facet_name);
        }

        return facet;
    };

    that.redirect = function() {

        var facet = that.get_redirect_facet();
        if (!facet) return;
        navigation.show(facet);
    };

    var redirect_error_codes = [4001];

    that.redirect_error = function(error_thrown) {

        /*If the error is in talking to the server, don't attempt to redirect,
          as there is nothing any other facet can do either. */
        for (var i=0; i<redirect_error_codes.length; i++) {
            if (error_thrown.code === redirect_error_codes[i]) {
                that.redirect();
                return;
            }
        }
    };

    that.init_facet = function() {

        that.action_state.init(that);
        that.actions.init(that);
        that.header.init();
        on(that.state, 'set', that.on_state_set);

        var buttons_spec = {
            $factory: IPA.control_buttons_widget,
            name: 'control-buttons',
            'class': 'control-buttons',
            buttons: spec.control_buttons
        };

        that.control_buttons = IPA.build(buttons_spec);
        that.control_buttons.init(that);
    };

    if (!no_init) that.init_facet();

    // methods that should be invoked by subclasses
    that.facet_create = that.create;
    that.facet_create_header = that.create_header;
    that.facet_create_content = that.create_content;
    that.facet_needs_update = that.needs_update;
    that.facet_show = that.show;
    that.facet_hide = that.hide;
    that.facet_load = that.load;

    return that;
};

exp.facet_header = IPA.facet_header = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    that.facet = spec.facet;

    that.init = function() {

        if (that.facet.header_actions) {

            var widget_builder = IPA.widget_builder({
                widget_options: {
                    entity: that.facet.entity,
                    facet: that.facet
                }
            });

            var widget = {
                $factory: IPA.action_list_widget,
                actions: that.facet.header_actions
            };

            that.action_list = widget_builder.build_widget(widget);
            that.action_list.init(that.facet);
        }

        that.facet.action_state.changed.attach(that.update_summary);

        that.title_widget = IPA.facet_title();
    };

    that.select_tab = function() {
        if (that.facet.disable_facet_tabs) return;

        $(that.facet_tabs).find('a').removeClass('selected');
        var facet_name = that.facet.name;

        if (!facet_name || facet_name === 'default') {
            that.facet_tabs.find('a:first').addClass('selected');
        } else {
            that.facet_tabs.find('a#' + facet_name ).addClass('selected');
        }
    };

    that.set_pkey = function(value) {

        if (!value) return;

        var key, i;
        var pkey_max = that.get_max_pkey_length();
        var limited_value = IPA.limit_text(value, pkey_max);

        if (!that.facet.disable_breadcrumb) {
            var breadcrumb = [];

            // all pkeys should be available in facet
            var keys = that.facet.get_pkeys();

            var entity = that.facet.entity.get_containing_entity();
            i = keys.length - 2; //set pointer to first containing entity

            while (entity) {
                key = keys[i];
                breadcrumb.unshift($('<a/>', {
                    'class': 'breadcrumb-element',
                    text: key,
                    title: entity.metadata.label_singular,
                    click: function(entity) {
                        return function() {
                            navigation.show_entity(entity.name, 'default');
                            return false;
                        };
                    }(entity)
                }));

                entity = entity.get_containing_entity();
                i--;
            }

            //calculation of breadcrumb keys length
            keys.push(value);
            var max_bc_l = 140; //max chars which can fit on one line
            var max_key_l = (max_bc_l / keys.length) - 4; //4 chars as divider
            var bc_l = 0;
            var to_limit = keys.length;

            //count how many won't be limited and how much space they take
            for (i=0; i<keys.length; i++) {
                var key_l = keys[i].length;
                if (key_l <= max_key_l) {
                    to_limit--;
                    bc_l += key_l + 4;
                }
            }

            max_key_l = ((max_bc_l - bc_l) / to_limit) - 4;


            that.path.empty();

            for (i=0; i<breadcrumb.length; i++) {
                var item = breadcrumb[i];
                key = IPA.limit_text(keys[i], max_key_l);
                item.text(key);

                that.path.append(' &raquo; ');
                that.path.append(item);
            }

            that.path.append(' &raquo; ');

            key = IPA.limit_text(keys[i], max_key_l);

            $('<span>', {
                'class': 'breadcrumb-element',
                title: value,
                text: key
            }).appendTo(that.path);
        }

        var title_info = {
            title: that.facet.label,
            pkey: limited_value,
            pkey_tooltip: value
        };
        that.title_widget.update(title_info);

        that.adjust_elements();
    };

    that.create_facet_link = function(container, other_facet) {

        var li = $('<li/>', {
            name: other_facet.name,
            title: other_facet.name,
            click: function() {
                if (li.hasClass('entity-facet-disabled')) {
                    return false;
                }

                var pkeys = that.facet.get_pkeys();
                navigation.show(other_facet, pkeys);

                return false;
            }
        }).appendTo(container);

        $('<a/>', {
            text: other_facet.tab_label,
            id: other_facet.name
        }).appendTo(li);
    };

    that.create_facet_group = function(container, facet_group) {

        var section = $('<div/>', {
            name: facet_group.name,
            'class': 'facet-group'
        }).appendTo(container);

        $('<div/>', {
            'class': 'facet-group-label'
        }).appendTo(section);

        var ul = $('<ul/>', {
            'class': 'facet-tab'
        }).appendTo(section);

        var facets = facet_group.facets.values;
        for (var i=0; i<facets.length; i++) {
            var facet = facets[i];
            that.create_facet_link(ul, facet);
        }
    };

    that.create = function(container) {

        that.container = container;

        if (!that.facet.disable_breadcrumb) {
            that.breadcrumb = $('<div/>', {
                'class': 'breadcrumb'
            }).appendTo(container);

            that.back_link = $('<span/>', {
                'class': 'back-link'
            }).appendTo(that.breadcrumb);

            var redirect_facet = that.facet.get_redirect_facet();

            $('<a/>', {
                text: redirect_facet.label,
                click: function() {
                    that.facet.redirect();
                    return false;
                }
            }).appendTo(that.back_link);


            that.path = $('<span/>', {
                'class': 'path'
            }).appendTo(that.breadcrumb);
        }

        that.title_widget.create(container);
        that.title_widget.update({ title: that.facet.label });

        if (that.action_list) {
            that.action_list_container = $('<div/>', {
                'class': 'facet-action-list'
            }).appendTo(container);

            that.action_list.create(that.action_list_container);
        }

        if (!that.facet.disable_facet_tabs) {
            that.facet_tabs = $('<div/>', {
                'class': 'facet-tabs'
            }).appendTo(container);

            var facet_groups = that.facet.entity.facet_groups.values;
            for (var i=0; i<facet_groups.length; i++) {
                var facet_group = facet_groups[i];
                if (facet_group.facets.length) {
                    that.create_facet_group(that.facet_tabs, facet_group);
                }
            }
        }
    };

    that.load = function(data) {
        if (!data) return;
        var result = data.result.result;
        if (!that.facet.disable_facet_tabs) {
            var pkey = that.facet.get_pkey();

            var facet_groups = that.facet.entity.facet_groups.values;
            for (var i=0; i<facet_groups.length; i++) {
                var facet_group = facet_groups[i];

                var span = $('.facet-group[name='+facet_group.name+']', that.facet_tabs);
                if (!span.length) continue;

                var label = facet_group.label;
                if (pkey && label) {
                    var limited_pkey = IPA.limit_text(pkey, 20);
                    label = label.replace('${primary_key}', limited_pkey);
                } else {
                    label = '';
                }

                var label_container = $('.facet-group-label', span);
                label_container.text(label);
                if (pkey) label_container.attr('title', pkey);

                var facets = facet_group.facets.values;
                for (var j=0; j<facets.length; j++) {
                    var facet = facets[j];
                    var link = $('li[name='+facet.name+'] a', span);

                    var values = result ? result[facet.name] : null;
                    if (values) {
                        link.text(facet.tab_label+' ('+values.length+')');
                    } else {
                        link.text(facet.tab_label);
                    }
                }
            }
        }
    };

    that.update_summary = function() {
        var summary = that.facet.action_state.summary();

        if (summary.state.length > 0) {
            var css_class = summary.state.join(' ');
            that.title_widget.set_class(css_class);
            that.title_widget.set_icon_tooltip(summary.description);
        }

        that.adjust_elements();
    };

    that.get_max_pkey_length = function() {

        var label_w, max_pkey_w, max_pkey_l, al, al_w, icon_w, char_w, container_w;

        container_w = that.container.width();
        icon_w = that.title_widget.icon.width();
        label_w = that.title_widget.title.width();
        char_w = label_w / that.title_widget.title.text().length;
        max_pkey_w = container_w - icon_w - label_w;
        max_pkey_w -= 10; //some space correction to be safe

        if (that.action_list) {
            al = that.action_list.container;
            al_w = al.width();

            max_pkey_w -=  al_w;
        }

        max_pkey_l = Math.ceil(max_pkey_w / char_w);

        return max_pkey_l;
    };

    that.adjust_elements = function() {

        if (that.action_list) {

            var action_list = that.action_list.container;
            var max_width = that.container.width();
            var al_width = action_list.width();
            var title_width = that.title_widget.title_container.width();
            var title_max = max_width - al_width;

            that.title_widget.set_max_width(title_max);
            action_list.css('left', title_width + 'px');
        }
    };

    that.clear = function() {
        that.load();
        if (that.action_list) that.action_list.clear();
    };

    return that;
};

exp.facet_title = IPA.facet_title = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    that.update = function(data) {

        var tooltip = data.tooltip || data.title;
        var pkey_tooltip = data.pkey_tooltip || data.pkey;
        var icon_tooltip = data.icon_tooltip || '';

        that.title.text(data.title);
        that.title.attr('title', tooltip);

        if (data.pkey) {
            that.title.text(data.title + ': ');
            that.pkey.text(data.pkey);
            that.pkey.attr('title', pkey_tooltip);
        }

        if (data.css_class) that.set_class(data.css_class);

        that.set_icon_tooltip(icon_tooltip);
    };

    that.create = function(container) {

        that.title_container = $('<div/>', {
            'class': 'facet-title'
        }).appendTo(container);

        that.icon = $('<div />', {
            'class': 'header-icon'
        }).appendTo(that.title_container);

        var h3 = $('<h3/>').appendTo(that.title_container);

        that.title = $('<span/>').appendTo(h3);

        that.pkey = $('<span/>', {
            'class': 'facet-pkey'
        }).appendTo(h3);
    };

    that.set_max_width = function(width) {
        that.title_container.css('max-width', width+'px');
    };

    that.set_class = function(css_class) {

        if (that.css_class) {
            that.title_container.removeClass(that.css_class);
        }

        if (css_class) {
            that.title_container.addClass(css_class);
        }

        that.css_class = css_class;
    };

    that.set_icon_tooltip = function(tooltip) {
        that.icon.attr('title', tooltip);
    };

    return that;
};

exp.table_facet = IPA.table_facet = function(spec, no_init) {

    spec = spec || {};

    var that = IPA.facet(spec, no_init);

    that.managed_entity = spec.managed_entity ? IPA.get_entity(spec.managed_entity) : that.entity;

    that.pagination = spec.pagination === undefined ? true : spec.pagination;
    that.search_all_entries = spec.search_all_entries;
    that.sort_enabled = spec.sort_enabled === undefined ? true : spec.sort_enabled;
    that.selectable = spec.selectable === undefined ? true : spec.selectable;
    that.select_changed = IPA.observer();

    that.row_enabled_attribute = spec.row_enabled_attribute;
    that.row_disabled_attribute = spec.row_disabled_attribute;
    that.details_facet_name = spec.details_facet || 'default';

    that.table_name = spec.table_name;

    that.columns = $.ordered_map();

    that.get_columns = function() {
        return that.columns.values;
    };

    that.get_column = function(name) {
        return that.columns.get(name);
    };

    that.add_column = function(column) {
        column.entity = that.managed_entity;
        column.facet = that;
        that.columns.put(column.name, column);
    };

    that.create_column = function(spec) {
        var column;
        if (spec instanceof Object) {
            var factory = spec.$factory || IPA.column;
        } else {
            factory = IPA.column;
            spec = { name: spec };
        }

        spec.entity = that.managed_entity;
        column = factory(spec);

        that.add_column(column);
        return column;
    };

    that.column = function(spec){
        that.create_column(spec);
        return that;
    };

    that.create_content = function(container) {
        that.table.create(container);
    };

    that.load = function(data) {
        that.facet_load(data);

        if (!data) {
            that.table.empty();
            that.table.summary.text('');
            that.table.pagination_control.css('visibility', 'hidden');
            return;
        }

        that.table.current_page = 1;
        that.table.total_pages = 1;

        if (that.pagination) {
            that.load_page(data);
        } else {
            that.load_all(data);
        }

        that.table.current_page_input.val(that.table.current_page);
        that.table.total_pages_span.text(that.table.total_pages);

        that.table.pagination_control.css('visibility', 'visible');

        that.post_load.notify([data], that);
        that.clear_expired_flag();
    };


    that.load_all = function(data) {

        var result = data.result.result;
        var records = [];
        for (var i=0; i<result.length; i++) {
            var record = that.table.get_record(result[i], 0);
            records.push(record);
        }
        that.load_records(records);

        if (data.result.truncated) {
            var message = text.get('@i18n:search.truncated');
            message = message.replace('${counter}', data.result.count);
            that.table.summary.text(message);
        } else {
            that.table.summary.text(data.result.summary || '');
        }
    };

    that.get_records_map = function(data) {

        var records_map = $.ordered_map();

        var result = data.result.result;
        var pkey_name = that.managed_entity.metadata.primary_key;

        for (var i=0; i<result.length; i++) {
            var record = result[i];
            var pkey = record[pkey_name];
            if (pkey instanceof Array) pkey = pkey[0];
            records_map.put(pkey, record);
        }

        return records_map;
    };

    that.load_page = function(data) {

        // get primary keys (and the complete records if search_all_entries is true)
        var records_map = that.get_records_map(data);

        var total = records_map.length;
        that.table.total_pages = total ? Math.ceil(total / that.table.page_length) : 1;

        delete that.table.current_page;

        var page = parseInt(that.state.page, 10) || 1;
        if (page < 1) {
            that.state.set({page: 1});
            return;
        } else if (page > that.table.total_pages) {
            that.state.set({page: that.table.total_pages});
            return;
        }
        that.table.current_page = page;

        if (!total) {
            that.table.summary.text(text.get('@i18n:association.no_entries'));
            that.load_records([]);
            return;
        }

        // calculate the start and end of the current page
        var start = (that.table.current_page - 1) * that.table.page_length + 1;
        var end = that.table.current_page * that.table.page_length;
        end = end > total ? total : end;

        var summary = text.get('@i18n:association.paging');
        summary = summary.replace('${start}', start);
        summary = summary.replace('${end}', end);
        summary = summary.replace('${total}', total);
        that.table.summary.text(summary);

        // sort map based on primary keys
        if (that.sort_enabled) {
            records_map = records_map.sort();
        }

        // trim map leaving the entries visible in the current page only
        records_map = records_map.slice(start-1, end);

        var columns = that.table.columns.values;
        if (columns.length == 1) { // show primary keys only
            that.load_records(records_map.values);
            return;
        }

        if (that.search_all_entries) {
            // map contains the primary keys and the complete records
            that.load_records(records_map.values);
            return;
        }

        // get the complete records
        that.get_records(
            records_map.keys,
            function(data, text_status, xhr) {
                var results = data.result.results;
                for (var i=0; i<records_map.length; i++) {
                    var pkey = records_map.keys[i];
                    var record = records_map.get(pkey);
                    // merge the record obtained from the refresh()
                    // with the record obtained from get_records()
                    $.extend(record, results[i].result);
                }
                that.load_records(records_map.values);
            },
            function(xhr, text_status, error_thrown) {
                that.load_records([]);
                var summary = that.table.summary.empty();
                summary.append(error_thrown.name+': '+error_thrown.message);
            }
        );
    };

    that.load_records = function(records) {
        that.table.empty();
        for (var i=0; i<records.length; i++) {
            that.add_record(records[i]);
        }
        that.table.set_values(that.selected_values);
    };

    that.add_record = function(record) {

        var tr = that.table.add_record(record);

        var attribute;
        if (that.row_enabled_attribute) {
            attribute = that.row_enabled_attribute;
        } else if (that.row_disabled_attribute) {
            attribute = that.row_disabled_attribute;
        } else {
            return;
        }

        var value = record[attribute];
        var column = that.table.get_column(attribute);
        if (column.formatter) value = column.formatter.parse(value);

        that.table.set_row_enabled(tr, value);
    };

    that.get_records_command_name = function() {
        return that.managed_entity.name+'_get_records';
    };

    that.create_get_records_command = function(pkeys, on_success, on_error) {

        var batch = IPA.batch_command({
            name: that.get_records_command_name(),
            on_success: on_success,
            on_error: on_error
        });

        for (var i=0; i<pkeys.length; i++) {
            var pkey = pkeys[i];

            var command = IPA.command({
                entity: that.table.entity.name,
                method: 'show',
                args: [pkey]
            });

            if (that.table.entity.has_members()) {
                command.set_options({no_members: true});
            }

            batch.add_command(command);
        }

        return batch;
    };

    that.get_records = function(pkeys, on_success, on_error) {

        var batch = that.create_get_records_command(pkeys, on_success, on_error);

        batch.execute();
    };

    that.get_selected_values = function() {
        return that.table.get_selected_values();
    };

    that.init_table = function(entity) {

        that.table = IPA.table_widget({
            'class': 'content-table',
            name: that.table_name || entity.metadata.primary_key,
            label: entity.metadata.label,
            entity: entity,
            pagination: true,
            scrollable: true,
            selectable: that.selectable && !that.read_only
        });

        var columns = that.columns.values;
        for (var i=0; i<columns.length; i++) {
            var column = columns[i];

            var metadata = IPA.get_entity_param(entity.name, column.name);
            column.primary_key = metadata && metadata.primary_key;
            column.link = (column.link === undefined ? true : column.link) && column.primary_key;

            if (column.link && column.primary_key) {
                column.link_handler = function(value) {
                    var pkeys = [value];

                    // for nested entities
                    var containing_entity = entity.get_containing_entity();
                    if (containing_entity && that.entity.name === containing_entity.name) {
                        pkeys = that.get_pkeys();
                        pkeys.push(value);
                    }

                    navigation.show_entity(entity.name, that.details_facet_name, pkeys);
                    return false;
                };
            }

            that.table.add_column(column);
        }

        that.table.select_changed = function() {
            that.selected_values = that.get_selected_values();
            that.select_changed.notify([that.selected_values]);
        };

        that.table.prev_page = function() {
            if (that.table.current_page > 1) {
                var page = that.table.current_page - 1;
                that.set_expired_flag();
                that.state.set({page: page});
            }
        };

        that.table.next_page = function() {
            if (that.table.current_page < that.table.total_pages) {
                var page = that.table.current_page + 1;
                that.set_expired_flag();
                that.state.set({page: page});
            }
        };

        that.table.set_page = function(page) {
            if (page < 1) {
                page = 1;
            } else if (page > that.total_pages) {
                page = that.total_pages;
            }
            that.set_expired_flag();
            that.state.set({page: page});
        };
    };

    that.init_table_columns = function() {
        var columns = spec.columns || [];
        for (var i=0; i<columns.length; i++) {
            that.create_column(columns[i]);
        }
    };

    if (!no_init) that.init_table_columns();

    that.table_facet_create_get_records_command = that.create_get_records_command;

    return that;
};

exp.facet_group = IPA.facet_group = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    that.name = spec.name;
    that.label = text.get(spec.label);

    that.facets = $.ordered_map();

    that.add_facet = function(facet) {
        that.facets.put(facet.name, facet);
    };

    that.get_facet = function(name) {
        return that.facets.get(name);
    };

    that.get_facet_index = function(name) {
        return that.facets.get_key_index(name);
    };

    that.get_facet_by_index = function(index) {
        return that.facets.get_value_by_index(index);
    };

    that.get_facet_count = function(index) {
        return that.facets.length;
    };

    return that;
};

exp.action = IPA.action = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    that.name = spec.name;
    that.label = text.get(spec.label);

    that.enabled = spec.enabled !== undefined ? spec.enabled : true;
    that.enable_cond = spec.enable_cond || [];
    that.disable_cond = spec.disable_cond || [];
    that.enabled_changed = IPA.observer();

    that.visible = spec.visible !== undefined ? spec.visible : true;
    that.show_cond = spec.show_cond || [];
    that.hide_cond = spec.hide_cond || [];
    that.visible_changed = IPA.observer();

    that.handler = spec.handler;

    that.needs_confirm = spec.needs_confirm !== undefined ? spec.needs_confirm : false;
    that.confirm_msg = text.get(spec.confirm_msg || '@i18n:actions.confirm');

    that.confirm_dialog = spec.confirm_dialog !== undefined ? spec.confirm_dialog :
                                                              IPA.confirm_dialog;



    that.execute_action = function(facet, on_success, on_error) {

        if (that.handler) {
            that.handler(facet, on_success, on_error);
        }
    };

    that.execute = function(facet, on_success, on_error) {

        if (!that.enabled || !that.visible) return;

        if (that.needs_confirm) {

            var confirmed = false;

            if (that.confirm_dialog) {

                that.dialog = IPA.build(that.confirm_dialog);
                that.update_confirm_dialog(facet);
                that.dialog.on_ok = function () {
                    that.execute_action(facet, on_success, on_error);
                };
                that.dialog.open();
            } else {
                var msg = that.get_confirm_message(facet);
                confirmed = IPA.confirm(msg);
            }

            if (!confirmed) return;
        }

        that.execute_action(facet, on_success, on_error);
    };

    that.update_confirm_dialog = function(facet) {
        that.dialog.message = that.get_confirm_message(facet);
    };

    that.get_confirm_message = function(facet) {
        return that.confirm_msg;
    };

    that.set_enabled = function(enabled) {

        var old = that.enabled;

        that.enabled = enabled;

        if (old !== that.enabled) {
            that.enabled_changed.notify([that.enabled], that);
        }
    };

    that.set_visible = function(visible) {

        var old = that.visible;

        that.visible = visible;

        if (old !== that.visible) {
            that.visible_changed.notify([that.visible], that);
        }
    };

    return that;
};

exp.action_holder = IPA.action_holder = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    that.actions = $.ordered_map();

    that.init = function(facet) {

        var i, action, actions;

        that.facet = facet;
        actions = builder.build('action', spec.actions) || [];

        for (i=0; i<actions.length; i++) {
            action = actions[i];
            that.actions.put(action.name, action);
        }

        that.facet.action_state.changed.attach(that.state_changed);
        that.facet.post_load.attach(that.on_load);
    };

    that.state_changed = function(state) {

        var actions, action, i, enabled, visible;

        actions = that.actions.values;

        for (i=0; i<actions.length; i++) {

            action = actions[i];

            enabled = IPA.eval_cond(action.enable_cond, action.disable_cond, state);
            visible = IPA.eval_cond(action.show_cond, action.hide_cond, state);
            action.set_enabled(enabled);
            action.set_visible(visible);
        }
    };

    that.get = function(name) {
        return that.actions.get(name);
    };

    that.add = function(action) {
        that.actions.put(action.name, action);
    };

    that.on_load = function() {
        var state = that.facet.action_state.get();
        that.state_changed(state);
    };

    return that;
};

exp.state = IPA.state = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    that.state = $.ordered_map();

    //when state changes. Params: state, Context: this
    that.changed = IPA.observer();

    that.evaluators = builder.build('state_evaluator', spec.evaluators) || [];
    that.summary_evaluator = builder.build('', spec.summary_evaluator || IPA.summary_evaluator);

    that.summary_conditions = builder.build('', spec.summary_conditions) || [];

    that.init = function(facet) {

        var i, evaluator;

        that.facet = facet;

        for (i=0; i<that.evaluators.length; i++) {
            evaluator = that.evaluators[i];
            evaluator.init(facet);
            evaluator.changed.attach(that.on_eval_changed);
        }
    };

    that.on_eval_changed = function() {

        var evaluator = this;

        that.state.put(evaluator.name, evaluator.state);

        that.notify();
    };

    that.get = function() {

        var state, i;

        state = [];

        var values = that.state.values;

        for (i=0; i<values.length; i++) {
            $.merge(state, values[i]);
        }

        return state;
    };

    that.summary = function() {

        var summary = that.summary_evaluator.evaluate(that);
        return summary;
    };

    that.notify = function(state) {

        state = state || that.get();

        that.changed.notify([state], that);
    };

    return that;
};

exp.summary_evaluator = IPA.summary_evaluator = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    that.evaluate = function(state) {

        var conds, cond, i, summary, state_a;

        conds = state.summary_conditions;
        state_a = state.get();

        for (i=0; i<conds.length; i++) {
            cond = conds[i];
            if (IPA.eval_cond(cond.pos, cond.neg, state_a)) {
                summary = {
                    state: cond.state,
                    description: cond.description
                };
                break;
            }
        }

        summary = summary ||  {
            state: state_a,
            description: ''
        };

        return summary;
    };

    return that;
};

exp.state_evaluator = IPA.state_evaluator = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    that.name = spec.name || 'state_evaluator';
    that.event_name = spec.event;

    //when state changes. Params: state, Context: this
    that.changed = IPA.observer();
    that.state = [];
    that.first_pass = true;

    that.init = function(facet) {

        if (that.event_name && facet[that.event_name]) {
            facet[that.event_name].attach(that.on_event);
        }
    };

    that.on_event = function() {
    };

    that.notify_on_change = function(old_state) {

        if (that.first_pass || IPA.array_diff(that.state, old_state)) {
            that.changed.notify([that.state], that);
            that.first_pass = false;
        }
    };

    return that;
};

exp.dirty_state_evaluator = IPA.dirty_state_evaluator = function(spec) {

    spec = spec || {};

    spec.event = spec.event || 'dirty_changed';

    var that = IPA.state_evaluator(spec);
    that.name = spec.name || 'dirty_state_evaluator';

    that.on_event = function(dirty) {

        var old_state = that.state;
        that.state = [];

        if (dirty) {
            that.state.push('dirty');
        }

        that.notify_on_change(old_state);
    };

    return that;
};

exp.selected_state_evaluator = IPA.selected_state_evaluator = function(spec) {

    spec = spec || {};

    spec.event = spec.event || 'select_changed';

    var that = IPA.state_evaluator(spec);
    that.name = spec.name || 'selected_state_evaluator';

    that.on_event = function(selected) {

        var old_state = that.state;
        that.state = [];

        if (selected && selected.length > 0) {
            that.state.push('item-selected');
        }

        that.notify_on_change(old_state);
    };

    return that;
};

exp.self_service_state_evaluator = IPA.self_service_state_evaluator = function(spec) {

    spec = spec || {};

    spec.event = spec.event || 'post_load';

    var that = IPA.state_evaluator(spec);
    that.name = spec.name || 'self_service_state_evaluator';

    that.on_event = function() {

        var old_state = that.state;
        that.state = [];

        if (IPA.is_selfservice) {
            that.state.push('self-service');
        }

        that.notify_on_change(old_state);
    };

    return that;
};

exp.facet_attr_state_evaluator = IPA.facet_attr_state_evaluator = function(spec) {

    spec = spec || {};

    spec.event = spec.event || 'post_load';

    var that = IPA.state_evaluator(spec);
    that.name = spec.name || 'facet_attr_se';
    that.attribute = spec.attribute;
    that.value = spec.value;
    that.state_value = spec.state_value;

    that.on_event = function() {

        var old_state = that.state;
        that.state = [];

        var facet = this;

        if (facet[that.attribute] === that.value) {
            that.state.push(that.state_value);
        }

        that.notify_on_change(old_state);
    };

    return that;
};

exp.read_only_state_evaluator = IPA.read_only_state_evaluator = function(spec) {

    spec = spec || {};

    spec.name = spec.name || 'read_only_se';
    spec.attribute = spec.attribute || 'read_only';
    spec.state_value = spec.state_value || 'read-only';
    spec.value = spec.value !== undefined ? spec.value : true;

    var that = IPA.facet_attr_state_evaluator(spec);
    return that;
};

exp.association_type_state_evaluator = IPA.association_type_state_evaluator = function(spec) {

    spec = spec || {};

    spec.name = spec.name || 'association_type_se';
    spec.attribute = spec.attribute || 'association_type';
    spec.state_value = spec.state_value || 'direct';
    spec.value = spec.value !== undefined ? spec.value : 'direct';

    var that = IPA.facet_attr_state_evaluator(spec);
    return that;
};

exp.action_button_widget = IPA.action_button_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.name = spec.name;
    that.label = text.get(spec.label);
    that.tooltip = text.get(spec.tooltip);
    that.href = spec.href || that.name;
    that.icon = spec.icon;

    that.action_name = spec.action || that.name;

    that.enabled = spec.enabled !== undefined ? spec.enabled : true;
    that.visible = spec.visible !== undefined ? spec.visible : true;

    that.show_cond = spec.show_cond || [];
    that.hide_cond = spec.hide_cond || [];

    that.init = function(facet) {

        that.facet = facet;
        that.action = that.facet.actions.get(that.action_name);
        that.action.enabled_changed.attach(that.set_enabled);
        that.action.visible_changed.attach(that.set_visible);
    };

    that.create = function(container) {

        that.widget_create(container);

        that.button_element = IPA.action_button({
            name: that.name,
            href: that.href,
            label: that.label,
            icon: that.icon,
            click: function() {
                that.on_click();
                return false;
            }
        }).appendTo(container);

        that.set_enabled(that.action.enabled);
        that.set_visible(that.action.visible);
    };

    that.on_click = function() {

        if (!that.enabled) return;

        that.action.execute(that.facet);
    };

    that.set_enabled = function(enabled) {
        that.widget_set_enabled(enabled);

        if (that.button_element) {
            if (enabled) {
                that.button_element.removeClass('action-button-disabled');
            } else {
                that.button_element.addClass('action-button-disabled');
            }
        }
    };

    that.set_visible = function(visible) {

        that.visible = visible;

        if (that.button_element) {
            if (visible) {
                that.button_element.show();
            } else {
                that.button_element.hide();
            }
        }
    };

    return that;
};

exp.control_buttons_widget = IPA.control_buttons_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.buttons = builder.build('widget', spec.buttons, {},
                                 { $factory: exp.action_button_widget} ) || [];

    that.init = function(facet) {

        var i;

        for (i=0; i<that.buttons.length; i++) {

            var button = that.buttons[i];
            button.init(facet);
        }
    };

    that.create = function(container) {

        that.container = $('<div/>', {
            'class': that['class']
        }).appendTo(container);

        for (var i=0; i<that.buttons.length; i++) {

            var button = that.buttons[i];
            button.create(that.container);
        }
    };

    return that;
};

exp.eval_cond = IPA.eval_cond = function(enable_cond, disable_cond, state) {

    var i, cond;

    if (disable_cond) {
        for (i=0; i<disable_cond.length; i++) {
            cond = disable_cond[i];
            if (state.indexOf(cond) > -1) {
                return false;
            }
        }
    }

    if (enable_cond) {
        for (i=0; i<enable_cond.length; i++) {
            cond = enable_cond[i];
            if (state.indexOf(cond) < 0) {
                return false;
            }
        }
    }

    return true;
};

exp.action_list_widget = IPA.action_list_widget = function(spec) {

    spec = spec || {};

    spec.widgets = spec.widgets || [
        {
            $type: 'html',
            css_class: 'separator'
        },
        {
            $type: 'select',
            name: 'action',
            undo: false
        },
        {
            $type: 'button',
            name: 'apply',
            label: '@i18n:actions.apply'
        }
    ];

    var that = IPA.composite_widget(spec);

    that.action_names = spec.actions || [];
    that.actions = $.ordered_map();

    that.init = function(facet) {

        var options, actions, action, name, i;

        that.facet = facet;

        that.action_select = that.widgets.get_widget('action');
        that.apply_button = that.widgets.get_widget('apply');

        that.action_select.value_changed.attach(that.on_action_change);
        that.apply_button.click = that.on_apply;

        for (i=0; i<that.action_names.length; i++) {
            name = that.action_names[i];
            action = that.facet.actions.get(name);
            that.add_action(action, true);
        }

        that.init_options();
    };

    that.add_action = function(action, batch) {
        that.actions.put(action.name, action);
        action.enabled_changed.attach(that.action_enabled_changed);
        action.visible_changed.attach(that.action_visible_changed);

        if(!batch) {
            that.init_options();
            that.recreate_options();
            that.select_first_enabled();
        }
    };

    that.init_options = function() {

        var options, actions, action, i;

        options = [];
        actions = that.actions.values;

        for (i=0; i< actions.length; i++) {
            action = actions[i];
            options.push({
                label: action.label,
                value: action.name
            });
        }

        that.action_select.options = options;
    };

    that.recreate_options = function() {

        that.action_select.create_options();
    };

    that.on_action_change = function() {

        var action = that.get_selected();
        that.apply_button.set_enabled(action.enabled);
    };

    that.on_apply = function() {

        var action = that.get_selected();

        if (action.enabled) {
            action.execute(that.facet,
                           that.on_action_success,
                           that.on_action_error);
        }
    };

    that.on_action_success = function() {
    };

    that.on_action_error = function() {
    };

    that.action_enabled_changed = function(enabled) {
        var action = this;
        var selected_action = that.get_selected();
        that.action_select.set_options_enabled(action.enabled, [action.name]);

        if (!action.enabled && action === selected_action) {
            that.select_first_enabled();
        }
    };

    that.get_selected = function() {
        var selected = that.action_select.save()[0];
        var action = that.actions.get(selected);
        return action;
    };

    that.get_disabled = function() {

        var disabled = [];
        var actions = that.action.values;

        for (var i=0; i< actions.length; i++) {
            var action = actions[i];
            if (!that.action.enabled) {
                disabled.push(action.name);
            }
        }

        return disabled;
    };

    that.select_first_enabled = function() {

        var actions = that.actions.values;

        var first = actions[0].name;

        for (var i=0; i< actions.length; i++) {
            var action = actions[i];
            if (action.enabled) {
                first = action.name;
                break;
            }
        }

        that.action_select.update([first]);
    };

    that.clear = function() {

        that.select_first_enabled();
    };

    return that;
};

var FacetState = exp.FacetState = declare([Stateful, Evented], {

    /**
     * Properties to ignore in clear and clone operation
     */
    _ignore_properties: {_watchCallbacks:1, onset:1,_updating:1, _inherited:1},

    /**
     * Gets object containing shallow copy of state's properties.
     */
    clone: function() {
        var clone = {};
        for(var x in this){
            if (this.hasOwnProperty(x) && !(x in this._ignore_properties)) {
                clone[x] = lang.clone(this[x]);
            }
        }
        return clone;
    },

    /**
     * Unset all properties.
     */
    clear: function() {
        var undefined;
        for(var x in this){
            if (this.hasOwnProperty(x) && !(x in this._ignore_properties)) {
                this.set(x, undefined);
            }
        }
        return this;
    },

    /**
     * Set a property
     *
     * Sets named properties on a stateful object and notifies any watchers of
     * the property. A programmatic setter may be defined in subclasses.
     *
     * Can be called with hash of name/value pairs.
     *
     * Raises 'set' event.
     */
    set: function(name, value) {

        var old_state;
        var updating = this._updating;
        if (!updating) old_state = this.clone();
        this._updating = true;
        this.inherited(arguments);
        if (!updating) {
            delete this._updating;
            var new_state = this.clone();
            this.emit('set', old_state, new_state);
        }

        return this;
    },

    /**
     * Set completely new state. Old state is cleared.
     *
     * Raises 'reset' event.
     */
    reset: function(object) {
        var old_state = this.clone();
        this._updating = true;
        this.clear();
        this.set(object);
        delete this._updating;
        var new_state = this.clone();
        this.emit('set', old_state, new_state);
        return this;
    }
});

// Facet builder and registry
var registry = new Singleton_registry();
reg.set('facet', registry);
builder.set('facet', registry.builder);

// Action builder and registry
exp.action_builder = builder.get('action');
exp.action_builder.factory = exp.action;
reg.set('action', exp.action_builder.registry);

// State Evaluator builder and registry
exp.state_evaluator_builder = builder.get('state_evaluator');
exp.state_evaluator.factory = exp.action;
reg.set('state_evaluator', exp.state_evaluator.registry);

exp.register = function() {
    var w = reg.widget;

    w.register('action_button', exp.action_button_widget);
    w.register('control_buttons', exp.control_buttons_widget);
    w.register('action_list', exp.action_list_widget);
};

phases.on('registration', exp.register);

return exp;
});
