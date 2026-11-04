// One scenario per run: a constant number of virtual users hammering one site of the harness for DURATION seconds. The result is written to /out/<host>.json.
import http from 'k6/http';
import { check } from 'k6';

const HOST = __ENV.TARGET_HOST || 'plain.test';
export const options = {
  scenarios: { load: { executor: 'constant-vus', vus: parseInt(__ENV.VUS || '64'), duration: (__ENV.DURATION || '20') + 's' } },
  discardResponseBodies: true,
};
const headers = {
  'Host': HOST,
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml', 'Accept-Language': 'en-US,en;q=0.9', 'Accept-Encoding': 'gzip, deflate, br',
};
export default function () {
  const r = http.get(`http://${__ENV.ENGINE || 'engine'}:18101/`, { headers });
  check(r, { 'status 200': (x) => x.status === 200 });
}
export function handleSummary(data) {
  const m = data.metrics;
  const out = { host: HOST, rps: m.http_reqs.values.rate, p50: m.http_req_duration.values.med, p95: m.http_req_duration.values['p(95)'], p99: m.http_req_duration.values['p(99)'],
                avg: m.http_req_duration.values.avg, failed: m.http_req_failed.values.rate, total: m.http_reqs.values.count };
  return { [`/out/${HOST}.json`]: JSON.stringify(out) };
}
