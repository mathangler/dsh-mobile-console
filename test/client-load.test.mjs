// Browser-half load test: run the client bundle in a minimal module-loader and
// React stub, then assert what it registers. This catches typos and API misuse
// in lib/client.js without a browser.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

/** Minimal React stub: enough for createElement plus the hooks the panel uses. */
function reactStub() {
  const createElement = (type, props, ...children) => ({ type, props: props ?? {}, children });
  return {
    createElement,
    useState: (initial) => [typeof initial === 'function' ? initial() : initial, () => {}],
    useEffect: () => {},
    useCallback: (fn) => fn,
    useRef: (initial) => ({ current: initial }),
  };
}

/** Load the bundle with a fake loader and return what it registered. */
async function loadClient() {
  const source = await readFile(new URL('../lib/client.js', import.meta.url), 'utf8');
  let loaded;
  const previousWindow = globalThis.window;
  const previousDocument = globalThis.document;
  globalThis.window = {
    __ModuleLoader__: {
      load: (definition) => {
        loaded = definition;
      },
    },
  };
  const head = [];
  globalThis.document = {
    head: { append: (node) => head.push(node) },
    createElement: () => ({ setAttribute: () => {}, remove: () => {}, style: {}, textContent: '' }),
  };
  try {
    // eslint-disable-next-line no-new-func
    new Function(source)();
  } finally {
    globalThis.window = previousWindow;
    globalThis.document = previousDocument;
  }
  assert.ok(loaded, 'the bundle must call window.__ModuleLoader__.load');
  return { definition: loaded, head };
}

test('the client bundle registers under the package name with the expected inject list', async () => {
  const { definition } = await loadClient();
  assert.equal(definition.id, 'dsh-mobile-console');
  assert.equal(typeof definition.factory, 'function');

  const module = definition.factory((name) => {
    if (name === 'react') return reactStub();
    throw new Error(`unexpected require(${name})`);
  });
  assert.deepEqual(module.inject, ['slots', 'locale']);
  assert.equal(typeof module.apply, 'function');
});

test('the client half registers one settings section and two stylesheets', async () => {
  const { definition } = await loadClient();
  const module = definition.factory((name) => {
    if (name === 'react') return reactStub();
    throw new Error(`unexpected require(${name})`);
  });

  const registered = [];
  const effects = [];
  const styles = [];
  const injected = [];
  const localeRegistrations = [];
  let localeListener;
  const ctx = {
    locale: {
      getSnapshot: () => ({ active: 'zh', locales: [{ id: 'en' }, { id: 'zh' }] }),
      register: (ns, id, dict) => {
        localeRegistrations.push({ ns, id, keys: Object.keys(dict).length });
        return () => {};
      },
      bind: () => (key) => (key === 'title' ? '手机访问' : key),
      subscribe: (fn) => {
        localeListener = fn;
        return () => {};
      },
    },
    effect: (fn, label) => {
      effects.push(label);
      return fn();
    },
    slots: {
      inject: (owner, install) => {
        injected.push(owner);
        install();
      },
      register: (options, component) => {
        registered.push({ options, component });
        return () => {};
      },
    },
  };
  // The panel's own state call is a network call; stub fetch so nothing escapes.
  const previousFetch = globalThis.fetch;
  const previousDocument = globalThis.document;
  const head = [];
  globalThis.fetch = () => Promise.resolve({ json: () => Promise.resolve({ ok: true, value: { config: { narrowEnhance: true } } }) });
  globalThis.document = {
    head: { append: (node) => { head.push(node); styles.push(node.textContent); } },
    createElement: () => {
      const node = {
        style: {},
        textContent: '',
        attrs: {},
        setAttribute: (name, value) => {
          node.attrs[name] = value;
        },
        remove: () => {},
      };
      return node;
    },
  };
  try {
    module.apply(ctx);
    // Let the stubbed state call settle so the media switch runs.
    await new Promise((resolve) => setTimeout(resolve, 0));
  } finally {
    globalThis.fetch = previousFetch;
    globalThis.document = previousDocument;
  }

  assert.deepEqual(injected, ['settings.section']);
  assert.equal(registered.length, 1);
  assert.equal(registered[0].options.name, 'settings.section');
  assert.equal(registered[0].options.id, 'mobile-console');
  assert.equal(typeof registered[0].component, 'function');
  assert.equal(registered[0].options.label(), '手机访问', 'the nav label follows the active locale');

  assert.equal(localeRegistrations.length, 2, 'one dictionary per installed locale');
  assert.deepEqual(localeRegistrations.map((r) => r.id), ['en', 'zh']);
  assert.ok(localeRegistrations.every((r) => r.ns === 'mobile-console' && r.keys > 20));
  assert.equal(typeof localeListener, 'function', 'the panel re-renders on locale change');

  assert.equal(styles.length, 2, 'panel styles plus the narrow-viewport stylesheet');
  assert.ok(styles[0].includes('.mc-root'), 'the panel stylesheet carries the panel classes');
  assert.ok(styles[1].includes('max-width: 1023px'), 'the narrow stylesheet is viewport-scoped');
  assert.deepEqual(
    effects.filter((label) => typeof label === 'string'),
    [
      'dsh-mobile-console: locale subscription',
      'dsh-mobile-console: panel styles',
      'dsh-mobile-console: narrow viewport tweaks',
    ],
  );
});

test('the panel renders through the translator before its first state arrives', async () => {
  const { definition } = await loadClient();
  const module = definition.factory((name) => {
    if (name === 'react') return reactStub();
    throw new Error(`unexpected require(${name})`);
  });
  const registered = [];
  const ctx = {
    locale: {
      getSnapshot: () => ({ active: 'en', locales: [{ id: 'en' }] }),
      register: () => () => {},
      bind: () => (key) => (key === 'title' ? 'Mobile Access' : key),
      subscribe: () => () => {},
    },
    effect: (fn) => fn(),
    slots: {
      inject: (_owner, install) => install(),
      register: (options, component) => registered.push({ options, component }),
    },
  };
  const previousFetch = globalThis.fetch;
  const previousDocument = globalThis.document;
  globalThis.fetch = () => Promise.resolve({ json: () => Promise.resolve({ ok: true, value: {} }) });
  globalThis.document = {
    head: { append: () => {} },
    createElement: () => ({ style: {}, setAttribute: () => {}, remove: () => {} }),
  };
  try {
    module.apply(ctx);
    // The stub's useState returns the initial value, so this is the pre-fetch
    // render: it must still be a real tree, translated through the locale service.
    const tree = registered[0].component();
    assert.equal(tree.type, 'div');
    assert.equal(tree.props.className, 'mc-root');
    assert.ok(JSON.stringify(tree).includes('Loading…'), 'the loading line comes from the dictionary');
  } finally {
    globalThis.fetch = previousFetch;
    globalThis.document = previousDocument;
  }
});
