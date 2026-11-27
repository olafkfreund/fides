import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import { test } from "node:test";

async function fixture(t, handler) {
  const server = createServer(handler).listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}`;
}

function configureApi(t, base) {
  const previous = process.env.NEXT_PUBLIC_API_BASE;
  if (base === undefined) delete process.env.NEXT_PUBLIC_API_BASE;
  else process.env.NEXT_PUBLIC_API_BASE = base;
  t.after(() => {
    if (previous === undefined) delete process.env.NEXT_PUBLIC_API_BASE;
    else process.env.NEXT_PUBLIC_API_BASE = previous;
  });
}

function json(res, items, link) {
  if (link) res.setHeader("Link", link);
  res.end(JSON.stringify(items));
}

test("list pagination uses the configured origin, retains credentials and leaves object and raw reads alone", async (t) => {
  const requests = [];
  const base = await fixture(t, (req, res) => {
    requests.push(req.url);
    switch (req.url) {
      case "/api/v1/search/artifacts?name=foo":
        json(res, [{ id: 1 }], '<?name=foo>; rel="self", <?name=foo&cursor=opaque%2Bvalue>; rel="next"');
        break;
      case "/api/v1/search/artifacts?name=foo&cursor=opaque%2Bvalue":
        json(res, [{ id: 2 }], '</api/v1/search/artifacts?name=foo&cursor=last>; rel="next"');
        break;
      case "/api/v1/search/artifacts?name=foo&cursor=last":
      case "/empty":
        json(res, []);
        break;
      case "/coverage":
        json(res, { controls: [] }, "</unexpected>; rel=next");
        break;
      case "/guide":
        res.setHeader("Link", "</unexpected>; rel=next");
        res.end("# Guide");
        break;
      default:
        res.writeHead(404).end();
    }
  });
  const nativeFetch = globalThis.fetch;
  t.mock.method(globalThis, "fetch", async (url, options) => {
    assert.equal(options.credentials, "include");
    return nativeFetch(url, options);
  });
  configureApi(t, base);
  globalThis.window = { location: { href: "http://portal.invalid/flows/" } };
  t.after(() => { delete globalThis.window; });

  const { apiGet, apiList, apiListPage } = await import("../src/lib/api.ts?configured");
  const path = "/api/v1/search/artifacts?name=foo";
  const first = await apiListPage(path);
  assert.deepEqual(first.items, [{ id: 1 }]);
  assert.equal(first.next.href, base + path + "&cursor=opaque%2Bvalue");
  assert.deepEqual(requests, [path]);
  assert.deepEqual(await apiList(path), [{ id: 1 }, { id: 2 }]);
  assert.deepEqual(await apiList("/empty"), []);
  assert.deepEqual(await apiGet("/coverage"), { controls: [] });
  assert.equal(await apiGet("/guide"), "# Guide");
  assert.deepEqual(requests, [path, path, path + "&cursor=opaque%2Bvalue", path + "&cursor=last", "/empty", "/coverage", "/guide"]);
});

test("list pagination refuses cross-origin next links and redirects before making contact", async (t) => {
  let foreignRequests = 0;
  const foreign = await fixture(t, (_, res) => { foreignRequests++; res.end("[]"); });
  const base = await fixture(t, (req, res) => {
    if (req.url === "/redirect?cursor=next") return res.writeHead(302, { Location: foreign }).end();
    if (req.url === "/redirect") return json(res, [], "<?cursor=next>; rel=next");
    if (req.url === "/cycle") return json(res, [], "</cycle>; rel=next");
    json(res, [], `<${foreign}>; rel=next`);
  });
  configureApi(t);
  globalThis.window = { location: { href: base + "/flows/" } };
  t.after(() => { delete globalThis.window; });

  const { apiList } = await import("../src/lib/api.ts?same-origin");
  await assert.rejects(apiList("/foreign"), /outside the Fides server/);
  await assert.rejects(apiList("/redirect"), /fetch failed/);
  await assert.rejects(apiList("/cycle"), /Repeated pagination link/);
  assert.equal(foreignRequests, 0);
});
