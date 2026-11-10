import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { JsStore } from './index.js';

const dirs = [];
after(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

function freshStore() {
  const parent = mkdtempSync(join(tmpdir(), 'chronicle-json-reads-'));
  dirs.push(parent);
  const path = join(parent, 'store');
  return { store: JsStore.openOrCreate({ path }), path };
}

const PROTO = '{"__proto__":{"a":1},"own":{"__proto__":"x","other":"y"},"list":[{"__proto__":1,"b":2},[{"__proto__":{"c":3}}]]}';
const NUL_KEY = '{"a\\u0000b":{"__proto__":null}}';
const BIG = '{"n":9007199254740993,"m":-9007199254740993,"f":0.1,"z":-0}';
const DECIMALS = '[9.498154036532778e-76,0.1,1e23,3.141592653589793]';
const ITEMS = ['{"__proto__":1,"b":2}', '[{"__proto__":{"c":3}}]', '{"__proto__":{"d":4}}'];

function readsAsParse(actual, text) {
  const walk = (a, e, at) => {
    if (e === null || typeof e !== 'object') {
      assert.ok(Object.is(a, e), `${at}: got ${String(a)} (${typeof a}), want ${String(e)} (${typeof e})`);
      return;
    }
    assert.equal(Array.isArray(a), Array.isArray(e), `${at}: array or object`);
    assert.equal(Object.getPrototypeOf(a), Object.getPrototypeOf(e), `${at}: prototype`);
    assert.deepEqual(Object.keys(a), Object.keys(e), `${at}: own keys`);
    for (const key of Object.keys(e)) walk(a[key], e[key], `${at}.${JSON.stringify(key)}`);
  };
  walk(actual, JSON.parse(text), '$');
}

function snapshot(store, id, text) {
  store.registerState({ id, strategy: 'snapshot' });
  return store.setState(id, Buffer.from(text));
}

for (const [what, text] of [
  ['own __proto__ keys at every depth', PROTO],
  ['a key holding NUL', NUL_KEY],
  ['integers past 2^53, a decimal and -0', BIG],
  ['decimals that need every digit to read back exactly', DECIMALS],
]) {
  test(`getStateJson reads stored JSON as JSON.parse does: ${what}`, () => {
    const { store } = freshStore();
    const at = Number(snapshot(store, 's', text).sequence);
    readsAsParse(store.getStateJson('s'), text);
    assert.equal(store.getState('s').toString('utf8'), text);
    assert.equal(store.getStateAt('s', at).toString('utf8'), text);
    store.close();
  });
}

test('an append-log state keeps every digit of its decimals, in its bytes and each read, before and after a reopen, its snapshots included', () => {
  const { store, path } = freshStore();
  const items = JSON.parse(DECIMALS).map((n) => JSON.stringify(n));
  const states = { log: {}, snapshotted: { deltaSnapshotEvery: 2, fullSnapshotEvery: 2 } };
  const at = {};
  for (const [id, cadence] of Object.entries(states)) {
    store.registerState({ id, strategy: 'append_log', ...cadence });
    items.forEach((text, index) =>
      index % 2 ? store.appendToState(id, Buffer.from(text)) : store.appendToStateJson(id, JSON.parse(text)));
    at[id] = Number(store.appendToState(id, Buffer.from('1')).sequence);
  }
  const check = (s) => {
    for (const id of Object.keys(states)) {
      readsAsParse(JSON.parse(s.getStateAt(id, at[id]).toString('utf8')).slice(0, -1), DECIMALS);
      readsAsParse(JSON.parse(s.getState(id).toString('utf8')).slice(0, -1), DECIMALS);
      readsAsParse(s.getStateJson(id).slice(0, -1), DECIMALS);
      readsAsParse(s.getStateJsonAt(id, at[id]).slice(0, -1), DECIMALS);
      items.forEach((text, index) => readsAsParse(s.getStateItemJson(id, index), text));
      s.getStateItemsJson(id, [0, 1, 2, 3]).forEach((value, index) => readsAsParse(value, items[index]));
    }
  };
  check(store);
  store.close();
  const reopened = JsStore.openOrCreate({ path });
  check(reopened);
  reopened.close();
});

test('a setStateJson / getStateJson round trip keeps own __proto__ keys', () => {
  const { store } = freshStore();
  store.registerState({ id: 's', strategy: 'snapshot' });
  store.setStateJson('s', JSON.parse(PROTO));
  readsAsParse(store.getStateJson('s'), PROTO);
  store.close();
});

test('getStateJsonAt reads a past state as JSON.parse does, before and after a reopen', () => {
  const { store, path } = freshStore();
  const at = Number(snapshot(store, 's', PROTO).sequence);
  store.setState('s', Buffer.from('{}'));
  readsAsParse(store.getStateJsonAt('s', at), PROTO);
  store.close();
  const reopened = JsStore.openOrCreate({ path });
  readsAsParse(reopened.getStateJsonAt('s', at), PROTO);
  reopened.close();
});

test('getStateItemJson and getStateItemsJson read items as JSON.parse does, the head record\'s own included', () => {
  const { store, path } = freshStore();
  store.registerState({ id: 'log', strategy: 'append_log' });
  store.appendToStateJson('log', JSON.parse(ITEMS[0]));
  store.appendToStateJson('log', JSON.parse(ITEMS[1]));
  store.appendToState('log', Buffer.from(ITEMS[2]));
  ITEMS.forEach((text, index) => readsAsParse(store.getStateItemJson('log', index), text));
  const many = store.getStateItemsJson('log', [2, 0, 1, -1]);
  [2, 0, 1].forEach((index, at) => readsAsParse(many[at], ITEMS[index]));
  assert.equal(many[3], null);
  store.close();
  const reopened = JsStore.openOrCreate({ path });
  ITEMS.forEach((text, index) => readsAsParse(reopened.getStateItemJson('log', index), text));
  reopened.close();
});

test('bytes that are not one JSON value still throw Deserialization from each read', () => {
  const { store } = freshStore();
  store.registerState({ id: 's', strategy: 'snapshot' });
  store.registerState({ id: 'log', strategy: 'append_log' });
  for (const text of ['{', '1e400', '"\\ud800"', '{"a":1} 2']) {
    const at = Number(store.setState('s', Buffer.from(text)).sequence);
    const coded = (error) => error.code === 'Deserialization';
    assert.throws(() => store.getStateJson('s'), coded, `getStateJson ${text}`);
    assert.throws(() => store.getStateJsonAt('s', at), coded, `getStateJsonAt ${text}`);
  }
  store.appendToStateJson('log', 1);
  store.appendToState('log', Buffer.from('{'));
  assert.throws(() => store.getStateItemJson('log', 1), (error) => error.code === 'Deserialization');
  assert.throws(() => store.getStateItemsJson('log', [1]), (error) => error.code === 'Deserialization');
  store.close();
});
