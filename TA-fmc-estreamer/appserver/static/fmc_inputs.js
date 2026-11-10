/* SPDX-License-Identifier: Apache-2.0 - Copyright 2026 Nikhil Chawla */
/*
 * TA-fmc-estreamer - Inputs page.
 * Lists FMC inputs (outputs, event types) and client certificates; add, edit, enable/disable,
 * restart, delete; upload certificates (PKCS12 from the FMC, or PEM).
 * Talks to /services/fmc_estreamer/inputs and /services/fmc_estreamer/certificates.
 */
require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc/simplexml/ready!'
], function ($, mvc, SearchManager) {
    'use strict';

    var APP = 'TA-fmc-estreamer';
    var service = mvc.createService({ owner: 'nobody', app: APP });
    var state = { inputs: [], certificates: [], certNames: [], indexes: [], status: {} };
    var $root = $('#fmc-inputs-app');

    // ------------------------------------------------------------ REST

    function parse(resp) {
        var data = resp && resp.data !== undefined ? resp.data : resp;
        if (typeof data === 'string') {
            try { data = JSON.parse(data); } catch (e) { /* keep text */ }
        }
        return data || {};
    }

    function errorText(err) {
        var data = parse(err);
        if (data && data.error) { return data.error; }
        if (data && data.messages && data.messages.length) { return data.messages[0].text; }
        return 'Request failed' + (err && err.status ? ' (HTTP ' + err.status + ')' : '');
    }

    function api(method, path, params, done, fail) {
        var url = '/services/fmc_estreamer/' + path;
        var args = $.extend({ output_mode: 'json' }, params || {});
        var cb = function (err, resp) {
            if (err) { (fail || showError)(errorText(err)); return; }
            done(parse(resp));
        };
        if (method === 'GET') { service.get(url, args, cb); } else { service.post(url, args, cb); }
    }

    // ------------------------------------------------------------ helpers

    function el(tag, attrs, children) {
        var $e = $('<' + tag + '>');
        $.each(attrs || {}, function (k, v) {
            if (k === 'text') { $e.text(v); } else if (k === 'class') { $e.addClass(v); } else { $e.attr(k, v); }
        });
        $.each(children || [], function (_, c) { if (c) { $e.append(c); } });
        return $e;
    }

    function button(label, cls, onClick) {
        return el('button', { type: 'button', 'class': 'btn ' + (cls || ''), text: label }).on('click', onClick);
    }

    function showError(text) { flash(text, 'fmc-error'); }

    function gb(bytes) {
        if (bytes === null || bytes === undefined) { return '?'; }
        var v = bytes / 1073741824;
        return (v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)) + ' GB';
    }

    function flash(text, cls) {
        var $m = $root.find('.fmc-flash');
        $m.removeClass('fmc-error fmc-ok').addClass(cls || 'fmc-ok').text(text).show();
        if (cls !== 'fmc-error') { setTimeout(function () { $m.fadeOut(); }, 6000); }
    }

    function fmtTime(epoch) {
        if (!epoch) { return ''; }
        var d = new Date(epoch * 1000);
        return d.toLocaleString();
    }

    // ------------------------------------------------------------ live status

    var statusSearch = new SearchManager({
        id: 'fmc_input_status',
        search: 'index=_internal sourcetype="fmc:estreamer:log" | eval err=if(log_level="ERROR", message, null()) ' +
            '| stats latest(_time) as last_seen latest(behind_min) as behind latest(written_eps) as eps ' +
            'latest(err) as last_error by input',
        earliest_time: '-15m',
        latest_time: 'now',
        autostart: false,
        preview: false,
        cache: false
    });
    statusSearch.data('results', { count: 0 }).on('data', function (results) {
        var data = results.data();
        var idx = {};
        $.each(data.fields, function (i, f) { idx[f] = i; });
        // Indexed logs (search heads, or forwarders that index locally). The
        // forwarder's own log files (state.local) win when they are newer.
        $.each(data.rows, function (_, row) {
            var found = {
                last_seen: parseFloat(row[idx.last_seen]),
                behind: row[idx.behind],
                eps: row[idx.eps],
                last_error: row[idx.last_error]
            };
            var local = state.status[row[idx.input]];
            if (!local || !local.last_seen || local.last_seen < found.last_seen) {
                state.status[row[idx.input]] = found;
            }
        });
        renderInputs();
    });

    function liveStatus(item) {
        if (item.disabled) { return el('span', { 'class': 'fmc-badge fmc-off', text: 'Disabled' }); }
        var s = state.status[item.name];
        if (!s || !s.last_seen) {
            return el('span', { 'class': 'fmc-badge fmc-wait', text: 'Enabled - no log in 15 min' });
        }
        var age = (Date.now() / 1000) - s.last_seen;
        var parts = [];
        var cls = 'fmc-good';
        var label = 'Running';
        if (s.behind !== undefined && s.behind !== null && s.behind !== '') {
            parts.push('behind ' + s.behind + ' min');
            if (parseFloat(s.behind) > 5) { cls = 'fmc-warn'; label = 'Behind'; }
        }
        if (s.eps) { parts.push(s.eps + '/s'); }
        if (s.paused) { cls = 'fmc-warn'; label = 'Paused - buffer full'; }
        if (age > 180) { cls = 'fmc-warn'; label = 'Quiet'; parts.push('last log ' + Math.round(age / 60) + ' min ago'); }
        if (s.last_error) { cls = 'fmc-bad'; label = 'Error'; }
        var $s = el('span', { 'class': 'fmc-badge ' + cls, text: label });
        var $wrap = el('div', {}, [$s, el('span', { 'class': 'fmc-sub', text: ' ' + parts.join(', ') })]);
        if (s.last_error) { $wrap.append(el('div', { 'class': 'fmc-sub fmc-errtext', text: s.last_error })); }
        return $wrap;
    }

    // ------------------------------------------------------------ load

    function load() {
        api('GET', 'inputs', {}, function (data) {
            state.inputs = data.inputs || [];
            state.certNames = data.certificates || [];
            state.indexes = data.indexes || [];
            state.status = {};
            $.each(state.inputs, function (_, item) {   // read from this instance's log files
                if (item.status && item.status.last_seen) { state.status[item.name] = item.status; }
            });
            renderInputs();
            statusSearch.startSearch();
        });
        loadCerts();
    }

    function loadCerts() {
        api('GET', 'certificates', {}, function (data) {
            state.certificates = data.certificates || [];
            renderCerts();
        });
    }

    // ------------------------------------------------------------ inputs table

    function renderInputs() {
        var $tb = $root.find('#fmc-input-rows').empty();
        if (!state.inputs.length) {
            $tb.append(el('tr', {}, [el('td', { colspan: 7, 'class': 'fmc-empty',
                text: 'No inputs yet. Upload the FMC client certificate, then add an input.' })]));
            return;
        }
        $.each(state.inputs, function (_, item) {
            var actions = el('div', { 'class': 'fmc-actions' }, [
                button('Edit', 'btn-small', function () { inputForm(item); }),
                button(item.disabled ? 'Enable' : 'Disable', 'btn-small', function () {
                    inputAction(item.disabled ? 'enable' : 'disable', item.name);
                }),
                item.disabled ? null : button('Restart', 'btn-small', function () { inputAction('restart', item.name); }),
                button('Delete', 'btn-small fmc-danger', function () {
                    if (window.confirm('Delete input "' + item.name + '"? Its event files still waiting on ' +
                            'disk are deleted and its file monitor removed; events already indexed stay, and ' +
                            'its bookmark is kept.')) {
                        inputAction('delete', item.name);
                    }
                })
            ]);
            $tb.append(el('tr', {}, [
                el('td', {}, [el('strong', { text: item.name })]),
                el('td', {}, [
                    el('div', { text: item.fmc_name || item.name }),
                    el('div', { 'class': 'fmc-sub', text: item.fmc_host + ':' + (item.fmc_port || '8302') })
                ]),
                el('td', { text: item.certificate }),
                el('td', {}, [
                    el('div', { text: outputText(item) }),
                    el('div', { 'class': 'fmc-sub', text: typesText(item) })
                ]),
                el('td', {}, [folderCell(item)]),
                el('td', {}, [liveStatus(item)]),
                el('td', {}, [actions])
            ]));
        });
    }

    function folderCell(item) {
        var b = item.buffer || {};
        var cap = parseFloat(item.buffer_max_gb || '200');
        var used = gb(b.bytes || 0) + ' of ' + cap + ' GB max';
        var $c = el('div', {}, [
            el('div', { 'class': 'fmc-path', text: item.output_path || '' }),
            el('div', { 'class': 'fmc-sub', text: used + ', ' + gb(b.free_bytes) + ' free' +
                (item.when_full === 'pause' ? ', full: pause' : ', full: delete oldest') })
        ]);
        if (b.free_bytes !== null && b.free_bytes !== undefined && b.free_bytes < cap * 1073741824) {
            $c.append(el('div', { 'class': 'fmc-sub fmc-errtext', text: 'Less free space than Max buffer' }));
        }
        return $c;
    }

    function inputAction(action, name) {
        api('POST', 'inputs', { action: action, name: name }, function (data) {
            state.inputs = data.inputs || [];
            renderInputs();
            loadCerts();
            flash('Input ' + name + ': ' + action + ' done.');
            if (action !== 'delete') { setTimeout(function () { statusSearch.startSearch(); }, 5000); }
        });
    }

    // ------------------------------------------------------------ input form

    function field(label, $input, help) {
        return el('div', { 'class': 'fmc-field' }, [
            el('label', { text: label }), $input, help ? el('div', { 'class': 'fmc-help', text: help }) : null
        ]);
    }

    function textInput(name, value, placeholder) {
        return el('input', { type: 'text', name: name, value: value || '', placeholder: placeholder || '' });
    }

    // Boolean settings are stored as 1 / 0; empty means the default.
    function isOn(value, dflt) {
        if (value === undefined || value === null || value === '') { return dflt; }
        return ['1', 'true', 'yes', 'on', 't', 'y'].indexOf(String(value).toLowerCase()) >= 0;
    }

    function checkbox(name, label, on, help) {
        var $box = el('input', { type: 'checkbox', name: name, 'class': 'fmc-check' });
        $box.prop('checked', !!on);
        return el('label', { 'class': 'fmc-checkline' }, [$box, el('span', { text: ' ' + label }),
            help ? el('span', { 'class': 'fmc-help', text: ' - ' + help }) : null]);
    }

    var EVENT_TYPES = [
        { key: 'connection_events', label: 'Connection events', dflt: true, help: 'binary connection' },
        { key: 'policy_violation_events', label: 'Policy violation (correlation)', dflt: false, help: 'binary connection' },
        { key: 'vpn_events', label: 'VPN login / logoff', dflt: false, help: 'binary connection' },
        { key: 'fireamp_events', label: 'FireAMP (AMP for Endpoints) malware', dflt: false, help: 'binary connection' },
        { key: 'file_events', label: 'File and file malware', dflt: false, help: 'FQE connection' },
        { key: 'intrusion_events', label: 'Intrusion', dflt: false, help: 'FQE connection' },
        { key: 'intrusion_packets', label: 'Intrusion packets', dflt: false, help: 'FQE connection' }
    ];

    function typesText(item) {
        var on = $.grep(EVENT_TYPES, function (t) { return isOn(item[t.key], t.dflt); });
        return $.map(on, function (t) { return t.label.split(' (')[0]; }).join(', ') || 'none';
    }

    function outputText(item) {
        var out = [];
        if (isOn(item.index_in_splunk, true)) { out.push('Splunk: ' + (item.index || 'default')); }
        if (isOn(item.write_cef, false)) { out.push('CEF files'); }
        return out.join(' + ') || 'none';
    }

    function select(name, options, value) {
        var $s = el('select', { name: name });
        $.each(options, function (_, o) {
            var opt = typeof o === 'string' ? { value: o, label: o } : o;
            $s.append(el('option', { value: opt.value, text: opt.label }));
        });
        $s.val(value);
        return $s;
    }

    function modal(title, $body, submitLabel, onSubmit) {
        var $overlay = el('div', { 'class': 'fmc-overlay' });
        var $msg = el('div', { 'class': 'fmc-form-error' }).hide();
        var close = function () { $overlay.remove(); };
        var $submit = button(submitLabel, 'btn-primary', function () {
            $msg.hide();
            $submit.prop('disabled', true);
            onSubmit(function (err) {
                $submit.prop('disabled', false);
                if (err) { $msg.text(err).show(); } else { close(); }
            });
        });
        var $box = el('div', { 'class': 'fmc-modal' }, [
            el('h3', { text: title }), $body, $msg,
            el('div', { 'class': 'fmc-modal-buttons' }, [button('Cancel', '', close), $submit])
        ]);
        $overlay.append($box).appendTo('body');
        $box.find('input:visible').first().trigger('focus');
        return $box;
    }

    function inputForm(item) {
        var editing = !!item;
        item = item || { fmc_port: '8302', index: '' };
        if (!state.certNames.length) {
            showError('Upload the FMC client certificate first (Client certificates, below).');
            return;
        }
        // Free text: a heavy forwarder can send to indexes that exist only on the
        // indexers / Splunk Cloud. Local indexes are offered as suggestions.
        var $index = textInput('index', item.index === 'default' ? '' : (item.index || ''), 'default');
        $index.attr({ list: 'fmc-index-list', autocomplete: 'off' });
        var $indexList = el('datalist', { id: 'fmc-index-list' });
        $.each(state.indexes, function (_, name) { $indexList.append(el('option', { value: name })); });
        var $adv = el('div', { 'class': 'fmc-advanced' }, [
            field('Start from', select('start_from', [
                { value: 'bookmark', label: 'Bookmark (resume; now if none yet)' },
                { value: 'now', label: 'Now, at every start (events while stopped are skipped)' }],
                item.start_from || 'bookmark')),
            field('Verify FMC certificate', select('verify_fmc', [
                { value: 'off', label: 'Off' },
                { value: 'on', label: 'On - needs the FMC CA in the uploaded client certificate' }],
                item.verify_fmc || 'off'),
                'On: the FMC\'s PKCS12 file includes its CA; for PEM, paste the CA after the client certificate.'),
            field('Decoder processes', textInput('workers', item.workers, '4')),
            field('Delete read files after (minutes)', textInput('delete_after_min', item.delete_after_min, '15'),
                'A file is deleted this long after Splunk has read all of it (0 = right away).'),
            field('New file at (MB)', textInput('rotate_mb', item.rotate_mb, '1024'),
                'A new event file also starts every hour.'),
            field('Log level', select('log_level', ['INFO', 'DEBUG', 'WARNING', 'ERROR'],
                (item.log_level || 'INFO').toUpperCase()))
        ]).hide();
        var $body = el('div', { 'class': 'fmc-form' }, [
            editing ? field('Name', el('div', { 'class': 'fmc-static', text: item.name }))
                : field('Name', textInput('name', '', 'e.g. fmc-east'), 'Letters, digits, . _ - (used in log and folder names)'),
            field('FMC host', textInput('fmc_host', item.fmc_host, 'IP address or host name')),
            field('FMC name (host field)', textInput('fmc_name', item.fmc_name, editing ? item.name : 'same as Name'),
                'Stored as host on the events. The FMC IP stays in every event as SourceHost.'),
            field('FMC port', textInput('fmc_port', item.fmc_port || '8302')),
            field('Client certificate', select('certificate', state.certNames, item.certificate || state.certNames[0])),
            field('Output', el('div', {}, [
                checkbox('index_in_splunk', 'Index in Splunk', isOn(item.index_in_splunk, true),
                    'JSON files read by this input\'s file monitor (sourcetype cisco:sfw:estreamer)'),
                checkbox('write_cef', 'Write CEF', isOn(item.write_cef, false),
                    'CEF files (.cef) in the same event folder, for a syslog agent to read and delete')
            ])),
            field('Index', el('div', {}, [$index, $indexList]),
                'Any index name; it does not have to exist on this forwarder (empty = default).'),
            field('Event types', el('div', {}, $.map(EVENT_TYPES, function (t) {
                return checkbox(t.key, t.label, isOn(item[t.key], t.dflt), t.help);
            })), 'File, intrusion and packet events come over a second (FQE) connection to the FMC, with the ' +
                'Cisco Security Cloud app\'s field names.'),
            field('Event folder', textInput('output_dir', item.output_dir, '$SPLUNK_HOME/var/log/fmc_estreamer'),
                'Events wait here until Splunk has read them: <folder>/<input name>/' +
                '<input>_<fmc>_<date>_<time>_w<n>.log (and .cef). Empty = $SPLUNK_HOME/var/log/fmc_estreamer.'),
            el('div', { 'class': 'fmc-warnbox', text: 'Depending on the event rate this folder can fill up ' +
                'quickly (a busy FMC can write 20-30 GB an hour, more with CEF as well). The user Splunk runs ' +
                'as must be able to write there; $SPLUNK_HOME/var/log is usually the safe choice. JSON files ' +
                'are deleted once Splunk has read them, CEF files by the syslog agent once it has read them; ' +
                'Max buffer caps the total of both.' }),
            field('Max buffer (GB)', textInput('buffer_max_gb', item.buffer_max_gb, '200'),
                'Most disk this input\'s files may use. Keep it below the free space of the folder.'),
            field('When the buffer or disk is full', select('when_full', [
                { value: 'delete_oldest', label: 'Delete oldest - keep collecting; delete the oldest files even if unread' },
                { value: 'pause', label: 'Pause - stop reading from the FMC until Splunk catches up (nothing unread is deleted)' }
            ], item.when_full || 'delete_oldest'), 'Applies when the files reach Max buffer and when less than ' +
                '1 GB is free on the folder\'s disk. The FMC keeps a fixed number of connection events ' +
                '(System > Configuration > Database), so on busy FMCs it may hold only minutes to hours. ' +
                'Pause only if the FMC holds days of events at its rate.'),
            el('a', { href: '#', 'class': 'fmc-toggle', text: 'Advanced settings' }).on('click', function (e) {
                e.preventDefault(); $adv.toggle();
            }),
            $adv
        ]);
        modal(editing ? 'Edit input ' + item.name : 'Add input', $body, editing ? 'Save' : 'Add', function (done) {
            var params = { action: editing ? 'edit' : 'create', name: editing ? item.name : $body.find('[name=name]').val() };
            $body.find('input[type=text], select').each(function () {
                var n = $(this).attr('name');
                if (n && n !== 'name') { params[n] = String($(this).val() || '').trim(); }
            });
            $body.find('input[type=checkbox]').each(function () {
                params[$(this).attr('name')] = $(this).prop('checked') ? '1' : '0';
            });
            if (params.index_in_splunk === '0' && params.write_cef === '0') {
                done('Choose at least one output: Index in Splunk and/or Write CEF.');
                return;
            }
            if (!$.grep(EVENT_TYPES, function (t) { return params[t.key] === '1'; }).length) {
                done('Choose at least one event type.');
                return;
            }
            if (!params.index) { params.index = 'default'; }
            api('POST', 'inputs', params, function (data) {
                state.inputs = data.inputs || [];
                renderInputs();
                loadCerts();
                var text = editing ? 'Input ' + item.name + ' saved; it restarts with the new settings.'
                    : 'Input ' + params.name + ' added and enabled. Status appears within a minute or two.';
                if (data.warning) { flash(text + ' Warning: ' + data.warning, 'fmc-error'); } else { flash(text); }
                setTimeout(function () { statusSearch.startSearch(); }, 8000);
                done();
            }, done);
        });
    }

    // ------------------------------------------------------------ certificates

    function renderCerts() {
        var $tb = $root.find('#fmc-cert-rows').empty();
        if (!state.certificates.length) {
            $tb.append(el('tr', {}, [el('td', { colspan: 6, 'class': 'fmc-empty',
                text: 'No client certificates. In the FMC: System > Integration > eStreamer > Create Client, ' +
                    'download the PKCS12 file, then upload it here.' })]));
            return;
        }
        $.each(state.certificates, function (_, c) {
            var expires = c.expires_epoch ? fmtTime(c.expires_epoch) : (c.not_after || '');
            var days = c.expires_epoch ? Math.floor((c.expires_epoch - Date.now() / 1000) / 86400) : null;
            var $exp = el('span', { text: expires });
            if (days !== null && days < 30) {
                $exp.addClass(days < 0 ? 'fmc-errtext' : 'fmc-warntext')
                    .text(expires + (days < 0 ? ' (expired)' : ' (' + days + ' days)'));
            }
            $tb.append(el('tr', {}, [
                el('td', {}, [el('strong', { text: c.name })]),
                el('td', { text: c.error || c.subject || '' }),
                el('td', {}, [$exp]),
                el('td', { text: (c.source || '').toUpperCase() + (c.uploaded ? ' - ' + c.uploaded + (c.uploaded_by ? ' by ' + c.uploaded_by : '') : '') }),
                el('td', { text: (c.used_by || []).join(', ') || '-' }),
                el('td', {}, [el('div', { 'class': 'fmc-actions' }, [
                    button('Replace', 'btn-small', function () { certForm(c.name); }),
                    button('Delete', 'btn-small fmc-danger', function () {
                        if (window.confirm('Delete client certificate "' + c.name + '"?')) {
                            api('POST', 'certificates', { action: 'delete', name: c.name }, function () {
                                flash('Certificate ' + c.name + ' deleted.');
                                load();
                            });
                        }
                    })
                ])])
            ]));
        });
    }

    function readFile(file, asText, done) {
        var reader = new FileReader();
        reader.onload = function () {
            done(asText ? reader.result : String(reader.result).split(',')[1] || '');
        };
        reader.onerror = function () { done(null); };
        if (asText) { reader.readAsText(file); } else { reader.readAsDataURL(file); }
    }

    function pemBox(name, label) {
        var $ta = el('textarea', { name: name, rows: 6, spellcheck: 'false',
            placeholder: '-----BEGIN ' + (name === 'key' ? 'PRIVATE KEY' : 'CERTIFICATE') + '-----' });
        var $file = el('input', { type: 'file' }).on('change', function () {
            if (this.files && this.files[0]) { readFile(this.files[0], true, function (t) { $ta.val(t || ''); }); }
        });
        return field(label, el('div', {}, [$file, $ta]), 'Choose the file or paste its text');
    }

    function certForm(replaceName) {
        var $p12file = el('input', { type: 'file', accept: '.pkcs12,.p12,.pfx' });
        var $p12 = el('div', { 'class': 'fmc-p12' }, [
            field('PKCS12 file from the FMC', $p12file),
            field('Password', el('input', { type: 'password', name: 'password', autocomplete: 'new-password' }),
                'The password set when the eStreamer client was created in the FMC')
        ]);
        var $pem = el('div', { 'class': 'fmc-pem' }, [
            pemBox('cert', 'Client certificate (PEM; optionally followed by the FMC CA certificate)'),
            pemBox('key', 'Private key (PEM, unencrypted)')
        ]).hide();
        var $format = select('format', [{ value: 'pkcs12', label: 'PKCS12 file from the FMC (.pkcs12)' },
            { value: 'pem', label: 'PEM certificate + key' }], 'pkcs12')
            .on('change', function () {
                $p12.toggle(this.value === 'pkcs12'); $pem.toggle(this.value === 'pem');
            });
        var $name = replaceName ? el('div', { 'class': 'fmc-static', text: replaceName })
            : textInput('name', '', 'e.g. fmc-east-client');
        var $body = el('div', { 'class': 'fmc-form' }, [
            field('Name', $name, replaceName ? 'Inputs using this name pick up the new certificate when they restart' : null),
            field('Format', $format), $p12, $pem,
            el('div', { 'class': 'fmc-help', text: 'Stored encrypted in Splunk\'s credential store. ' +
                'The private key is never shown again.' })
        ]);
        modal(replaceName ? 'Replace certificate ' + replaceName : 'Upload client certificate', $body, 'Upload',
            function (done) {
                var params = { action: 'upload', name: replaceName || String($body.find('[name=name]').val() || '').trim(),
                    format: $format.val() };
                var send = function () {
                    api('POST', 'certificates', params, function (data) {
                        var c = data.certificate || {};
                        flash('Uploaded ' + c.name + ' (' + (c.subject || '') + ', expires ' + (c.not_after || '?') + ').');
                        load();
                        done();
                    }, done);
                };
                if (params.format === 'pem') {
                    params.cert = $body.find('[name=cert]').val();
                    params.key = $body.find('[name=key]').val();
                    send();
                    return;
                }
                var file = $p12file[0].files && $p12file[0].files[0];
                if (!file) { done('Choose the PKCS12 file.'); return; }
                params.password = $body.find('[name=password]').val();
                readFile(file, false, function (b64) {
                    if (!b64) { done('Could not read the file.'); return; }
                    params.pkcs12 = b64;
                    send();
                });
            });
    }

    // ------------------------------------------------------------ page

    $root.empty().append(
        el('div', { 'class': 'fmc-flash' }).hide(),
        el('div', { 'class': 'fmc-section' }, [
            el('div', { 'class': 'fmc-head' }, [
                el('h2', { text: 'FMC inputs' }),
                el('div', {}, [
                    button('Refresh', '', load),
                    button('Add input', 'btn-primary', function () { inputForm(null); })
                ])
            ]),
            el('p', { 'class': 'fmc-help', text: 'One input per FMC. Each runs as its own process on this ' +
                'forwarder and writes the chosen event types for Splunk to index (sourcetype ' +
                'cisco:sfw:estreamer, host = FMC name, SourceHost = FMC IP) and/or as CEF files. ' +
                'Changes restart the input; it resumes from its bookmarks.' }),
            el('table', { 'class': 'table table-striped fmc-table' }, [
                el('thead', {}, [el('tr', {}, $.map(['Name', 'FMC', 'Certificate', 'Output and events', 'Event folder',
                    'Status', ''],
                    function (h) { return el('th', { text: h }); }))]),
                el('tbody', { id: 'fmc-input-rows' })
            ])
        ]),
        el('div', { 'class': 'fmc-section' }, [
            el('div', { 'class': 'fmc-head' }, [
                el('h2', { text: 'Client certificates' }),
                button('Upload certificate', 'btn-primary', function () { certForm(null); })
            ]),
            el('table', { 'class': 'table table-striped fmc-table' }, [
                el('thead', {}, [el('tr', {}, $.map(['Name', 'Subject', 'Expires', 'Uploaded', 'Used by', ''],
                    function (h) { return el('th', { text: h }); }))]),
                el('tbody', { id: 'fmc-cert-rows' })
            ])
        ])
    );
    load();
});
