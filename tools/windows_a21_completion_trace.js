/*
 * Minimal, privacy-safe completion trace for the pinned Dell A21 x64 stack.
 *
 * This deliberately does not hook capture functions, inspect arguments,
 * read memory, or observe the internal route.  The first full trace already
 * established the generic-0x6c route and CaptureStart-to-Update forwarding.
 * This reduced probe records only low-frequency function ordering and uint32
 * return statuses around UpdateEnrollment, commit, and discard.
 */

'use strict';

const BIP_NAME = 'bipdll.dll';
const state = {
  installed: false,
  updateCalls: 0,
  commitCalls: 0,
  discardCalls: 0,
};

function emit(event, fields) {
  const parts = ['cv2win-min', 'event=' + event];
  Object.keys(fields).forEach(function (key) {
    parts.push(key + '=' + String(fields[key]).replace(/\s+/g, '_'));
  });
  console.log(parts.join(' '));
}

function hookExport(module, name, callbacks) {
  const address = module.findExportByName(name);
  if (address === null)
    throw new Error('required export missing');
  Interceptor.attach(address, callbacks);
  emit('hook-installed', { symbol: name });
}

function hookStatusPair(module, name, kind) {
  hookExport(module, name, {
    onEnter: function () {
      if (kind === 'commit')
        this.call = ++state.commitCalls;
      else
        this.call = ++state.discardCalls;
      emit(kind + '-enter', { symbol: name, call: this.call });
    },
    onLeave: function (retval) {
      emit(kind + '-leave', {
        symbol: name,
        call: this.call,
        status: '0x' + retval.toUInt32().toString(16),
      });
    },
  });
}

function installHooks(module) {
  if (state.installed)
    return;
  if (Process.arch !== 'x64')
    throw new Error('unsupported architecture');

  state.installed = true;
  emit('trace-start', {
    profile: 'Dell_A21_x64_minimal_completion',
    argument_inspection: 'disabled',
    memory_reads: 'disabled',
    capture_hooks: 'disabled',
  });

  hookExport(module, 'CSS_FingerprintUpdateEnrollment', {
    onEnter: function () {
      this.call = ++state.updateCalls;
    },
    onLeave: function (retval) {
      emit('update-leave', {
        call: this.call,
        status: '0x' + retval.toUInt32().toString(16),
      });
    },
  });

  [
    'CSS_FingerprintCommitEnrollment',
    'CSS_FingerprintCommitFeatureSet',
    'cv_fingerprint_commit_enrollment',
    'cv_fingerprint_commit_feature_set',
  ].forEach(function (name) { hookStatusPair(module, name, 'commit'); });

  [
    'CSS_FingerprintDiscardEnrollment',
    'cv_fingerprint_discard_enrollment',
  ].forEach(function (name) { hookStatusPair(module, name, 'discard'); });

  emit('trace-ready', { action: 'start_fresh_Windows_Hello_enrollment' });
}

function tryInstall() {
  if (state.installed)
    return;
  const module = Process.findModuleByName(BIP_NAME);
  if (module !== null) {
    try {
      installHooks(module);
    } catch (error) {
      /* Frida error strings can contain process addresses; never print them. */
      emit('trace-fatal', { reason: 'hook_install_failed' });
    }
  }
}

setImmediate(tryInstall);
setInterval(tryInstall, 500);
