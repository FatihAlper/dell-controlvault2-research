/*
 * Privacy-safe Frida trace for the exact Dell/Broadcom A21 x64 stack.
 *
 * This script never reads a payload into a JavaScript array, never prints a
 * pointer/address, and never prints fingerprint, capture-ID, token, template,
 * or object bytes.  It records only call ordering, status codes, zero/nonzero
 * classifications, pointer equality, and the generic-vs-5880 branch choice.
 * The PowerShell runner validates all three loaded DLL hashes before loading
 * this script.
 */

'use strict';

const BIP_NAME = 'bipdll.dll';
const UPDATE_SELECTOR_TEST_RVA = 0x2d249;
const activeUpdates = new Map();
const state = {
  installed: false,
  updateCalls: 0,
  captureStartCalls: 0,
  commitCalls: 0,
  discardCalls: 0,
  previousUpdateInput: null,
  previousUpdateOutput: null,
  lastCaptureOutput: null,
};

function emit(event, fields) {
  const parts = ['cv2win', 'event=' + event];
  Object.keys(fields).forEach(function (key) {
    parts.push(key + '=' + String(fields[key]).replace(/\s+/g, '_'));
  });
  console.log(parts.join(' '));
}

function relation(current, previous) {
  if (current === null || current.isNull())
    return 'null';
  if (previous === null)
    return 'first';
  return current.equals(previous) ? 'same' : 'changed';
}

function byteClass(address) {
  if (address === null || address.isNull())
    return 'null';
  try {
    return address.readU8() === 0 ? 'zero' : 'nonzero';
  } catch (error) {
    return 'unreadable';
  }
}

function dwordClass(address) {
  if (address === null || address.isNull())
    return 'null';
  try {
    return address.readU32() === 0 ? 'zero' : 'nonzero';
  } catch (error) {
    return 'unreadable';
  }
}

function bufferClass(address, length) {
  if (address === null || address.isNull())
    return 'null';
  try {
    for (let index = 0; index < length; index++) {
      if (address.add(index).readU8() !== 0)
        return 'nonzero';
    }
    return 'zero';
  } catch (error) {
    return 'unreadable';
  }
}

function buffersEqual(left, right, length) {
  if (left === null || right === null || left.isNull() || right.isNull())
    return 'unavailable';
  try {
    for (let index = 0; index < length; index++) {
      if (left.add(index).readU8() !== right.add(index).readU8())
        return 'no';
    }
    return 'yes';
  } catch (error) {
    return 'unreadable';
  }
}

function stackArgumentPointer(context, argumentNumber) {
  /* Win64: return address + 32-byte shadow space, then argument five. */
  const offset = 0x28 + ((argumentNumber - 5) * Process.pointerSize);
  try {
    return context.rsp.add(offset).readPointer();
  } catch (error) {
    return null;
  }
}

function activeStack(threadId) {
  let stack = activeUpdates.get(threadId);
  if (stack === undefined) {
    stack = [];
    activeUpdates.set(threadId, stack);
  }
  return stack;
}

function hookExport(module, name, callbacks) {
  const address = module.findExportByName(name);
  if (address === null)
    throw new Error('required export missing: ' + name);
  Interceptor.attach(address, callbacks);
  emit('hook-installed', { symbol: name });
}

function hookSimpleStatus(module, name, kind) {
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
    throw new Error('unsupported architecture: ' + Process.arch);

  state.installed = true;
  emit('trace-start', {
    profile: 'Dell_A21_x64',
    payload_logging: 'disabled',
    pointer_logging: 'disabled',
  });

  hookExport(module, 'CSS_FingerprintCaptureStart', {
    onEnter: function (args) {
      this.call = ++state.captureStartCalls;
      this.output20 = args[2];
      emit('capture-start-enter', {
        call: this.call,
        selector_arg0: args[0].toUInt32(),
        mode_arg1: args[1].toUInt32(),
        output_presence: this.output20.isNull() ? 'null' : 'present',
      });
    },
    onLeave: function (retval) {
      state.lastCaptureOutput = this.output20;
      emit('capture-start-leave', {
        call: this.call,
        status: '0x' + retval.toUInt32().toString(16),
        output20_class: bufferClass(this.output20, 20),
      });
    },
  });

  hookExport(module, 'CSS_FingerprintSetCaptureMode', {
    onEnter: function (args) {
      emit('set-capture-mode-enter', { arg0: args[0].toUInt32() });
    },
    onLeave: function (retval) {
      emit('set-capture-mode-leave', {
        status: '0x' + retval.toUInt32().toString(16),
      });
    },
  });

  hookExport(module, 'CSS_FingerprintUpdateEnrollment', {
    onEnter: function (args) {
      const threadId = Process.getCurrentThreadId();
      this.threadId = threadId;
      this.call = ++state.updateCalls;
      this.input20 = args[0];
      this.completion = args[1];
      this.output20 = args[2];
      this.auxiliaryRequested = args[3].toUInt32();
      this.output4 = stackArgumentPointer(this.context, 5);
      this.route = 'not-observed';
      activeStack(threadId).push(this);

      emit('update-enter', {
        call: this.call,
        input_pointer_relation: relation(this.input20,
                                         state.previousUpdateInput),
        input_matches_capture_start: buffersEqual(this.input20,
                                                  state.lastCaptureOutput,
                                                  20),
        completion_pre: byteClass(this.completion),
        output20_pointer_relation: relation(this.output20,
                                            state.previousUpdateOutput),
        output20_pre: bufferClass(this.output20, 20),
        auxiliary_requested: this.auxiliaryRequested === 0 ? 'no' : 'yes',
        output4_pre: dwordClass(this.output4),
      });
      state.previousUpdateInput = this.input20;
      state.previousUpdateOutput = this.output20;
    },
    onLeave: function (retval) {
      const stack = activeUpdates.get(this.threadId);
      if (stack !== undefined) {
        stack.pop();
        if (stack.length === 0)
          activeUpdates.delete(this.threadId);
      }
      emit('update-leave', {
        call: this.call,
        route: this.route,
        status: '0x' + retval.toUInt32().toString(16),
        completion_post: byteClass(this.completion),
        output20_post: bufferClass(this.output20, 20),
        output4_post: dwordClass(this.output4),
      });
    },
  });

  Interceptor.attach(module.base.add(UPDATE_SELECTOR_TEST_RVA), {
    onEnter: function () {
      const stack = activeUpdates.get(Process.getCurrentThreadId());
      if (stack === undefined || stack.length === 0)
        return;
      const current = stack[stack.length - 1];
      current.route = (this.context.rax.toUInt32() & 0xff) === 0
        ? 'generic-0x6c'
        : 'bcm5880-host-template';
      emit('update-route', { call: current.call, route: current.route });
    },
  });
  emit('hook-installed', { symbol: 'bipdll+0x2d249' });

  [
    'CSS_FingerprintCommitEnrollment',
    'CSS_FingerprintCommitFeatureSet',
    'cv_fingerprint_commit_enrollment',
    'cv_fingerprint_commit_feature_set',
  ].forEach(function (name) { hookSimpleStatus(module, name, 'commit'); });

  [
    'CSS_FingerprintDiscardEnrollment',
    'cv_fingerprint_discard_enrollment',
  ].forEach(function (name) { hookSimpleStatus(module, name, 'discard'); });

  emit('trace-ready', { action: 'start_Windows_Hello_enrollment' });
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
