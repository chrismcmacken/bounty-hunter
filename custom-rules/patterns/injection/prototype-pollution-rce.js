// Test cases for prototype pollution to RCE rules
// Run with: semgrep --test custom-rules/patterns/injection/

// =============================================================================
// Rule 1: prototype-pollution-deep-merge
// =============================================================================

// ruleid: prototype-pollution-deep-merge
function vulnerableMerge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      target[key] = vulnerableMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// ruleid: prototype-pollution-deep-merge
function vulnerableExtend(target, source) {
  for (var key in source) {
    target[key] = source[key];
  }
  return target;
}

// ruleid: prototype-pollution-deep-merge
function vulnerableForEach(target, source) {
  Object.keys(source).forEach(function(key) {
    target[key] = source[key];
  });
  return target;
}

// ruleid: prototype-pollution-deep-merge
const vulnerableArrowForEach = (target, source) => {
  Object.keys(source).forEach((key) => {
    target[key] = source[key];
  });
  return target;
};

// ok: prototype-pollution-deep-merge
function safeMergeHasOwn(target, source) {
  for (let key in source) {
    if (source.hasOwnProperty(key)) {
      target[key] = source[key];
    }
  }
  return target;
}

// ok: prototype-pollution-deep-merge
function safeMergeObjectHasOwn(target, source) {
  for (let key in source) {
    if (Object.hasOwn(source, key)) {
      target[key] = source[key];
    }
  }
  return target;
}

// ok: prototype-pollution-deep-merge
function safeMergeFilterProto(target, source) {
  for (let key in source) {
    if (key === "__proto__" || key === "constructor") {
      continue;
    }
    target[key] = source[key];
  }
  return target;
}

// ok: prototype-pollution-deep-merge
function safeMergeContinueGuard(target, source) {
  for (let key in source) {
    if (!source.hasOwnProperty(key)) continue;
    target[key] = source[key];
  }
  return target;
}

// =============================================================================
// Rule 2: prototype-pollution-spread-http (taint mode)
// =============================================================================

const express = require('express');
const app = express();

// ruleid: prototype-pollution-spread-http
app.post('/vulnerable-spread', (req, res) => {
  const config = { ...req.body };
  res.json(config);
});

// ruleid: prototype-pollution-spread-http
app.post('/vulnerable-assign', (req, res) => {
  const config = Object.assign({}, req.body);
  res.json(config);
});

// ruleid: prototype-pollution-spread-http
app.get('/vulnerable-query-spread', (req, res) => {
  const options = { defaults: true, ...req.query };
  res.json(options);
});

// ok: prototype-pollution-spread-http
app.post('/safe-explicit-props', (req, res) => {
  const config = {
    name: req.body.name,
    value: req.body.value
  };
  res.json(config);
});

// ok: prototype-pollution-spread-http
app.post('/safe-json-sanitize', (req, res) => {
  const sanitized = JSON.parse(JSON.stringify(req.body));
  const config = { ...sanitized };
  res.json(config);
});

// =============================================================================
// Rule 3: prototype-pollution-object-assign
// =============================================================================

// ruleid: prototype-pollution-object-assign
app.post('/direct-spread-body', (req, res) => {
  const data = { ...req.body };
  process(data);
});

// ruleid: prototype-pollution-object-assign
app.get('/direct-spread-query', (req, res) => {
  const options = { ...req.query };
  render(options);
});

// ruleid: prototype-pollution-object-assign
app.post('/object-assign-body', (req, res) => {
  const config = {};
  Object.assign(config, req.body);
  save(config);
});

// ruleid: prototype-pollution-object-assign
app.post('/lodash-merge-body', (req, res) => {
  const defaults = { timeout: 5000 };
  _.merge(defaults, req.body);
  connect(defaults);
});

// ruleid: prototype-pollution-object-assign
app.post('/lodash-extend-body', (req, res) => {
  const options = {};
  _.extend(options, req.body);
});

// ruleid: prototype-pollution-object-assign
app.post('/lodash-defaults-deep', (req, res) => {
  const config = { nested: { value: 1 } };
  _.defaultsDeep(config, req.body);
});

// ok: prototype-pollution-object-assign
app.post('/safe-internal-spread', (req, res) => {
  const internal = getInternalConfig();
  const data = { ...internal };
});

// =============================================================================
// Rule 4: prototype-pollution-to-child-process
// =============================================================================

const { spawn, exec, execSync } = require('child_process');

// ruleid: prototype-pollution-to-child-process
app.post('/vulnerable-spawn', (req, res) => {
  const options = { ...req.body.options };
  spawn('node', ['script.js'], options);
});

// ruleid: prototype-pollution-to-child-process
app.post('/vulnerable-exec', (req, res) => {
  const config = Object.assign({}, req.body);
  exec('ls -la', config, (err, stdout) => {
    res.send(stdout);
  });
});

// ruleid: prototype-pollution-to-child-process
app.post('/vulnerable-execsync', (req, res) => {
  const opts = { ...req.query };
  const result = execSync('date', opts);
  res.send(result);
});

// ok: prototype-pollution-to-child-process
app.post('/safe-spawn-null-proto', (req, res) => {
  const options = Object.create(null);
  options.cwd = req.body.cwd;
  spawn('node', ['script.js'], options);
});

// ok: prototype-pollution-to-child-process
app.post('/safe-spawn-explicit-opts', (req, res) => {
  spawn('node', ['script.js'], { shell: false, cwd: '/tmp' });
});

// =============================================================================
// Rule 5: prototype-pollution-query-parser
// =============================================================================

// ruleid: prototype-pollution-query-parser
function parseQueryString(query) {
  const result = {};
  const pairs = query.split('&');
  for (const pair of pairs) {
    const [key, value] = pair.split('=');
    result[key] = decodeURIComponent(value);
  }
  return result;
}

// ruleid: prototype-pollution-query-parser
function decodeParams(str) {
  let result = {};
  str.split('&').forEach(pair => {
    const [k, v] = pair.split('=');
    result[k] = v;
  });
  return result;
}

// ruleid: prototype-pollution-query-parser
function extractCookies(cookieStr) {
  const result = {};
  cookieStr.split(';').forEach(cookie => {
    const [name, value] = cookie.trim().split('=');
    result[name] = value;
  });
  return result;
}

// ok: prototype-pollution-query-parser
function safeParseQueryString(query) {
  const result = Object.create(null);
  const pairs = query.split('&');
  for (const pair of pairs) {
    const [key, value] = pair.split('=');
    result[key] = decodeURIComponent(value);
  }
  return result;
}

// ok: prototype-pollution-query-parser
function parseQueryStringFiltered(query) {
  const result = {};
  const pairs = query.split('&');
  for (const pair of pairs) {
    const [key, value] = pair.split('=');
    if (key === "__proto__") {
      continue;
    }
    result[key] = decodeURIComponent(value);
  }
  return result;
}

// ok: prototype-pollution-query-parser
function notAParseFunctionButAssigns(data) {
  const result = {};
  result['staticKey'] = data.value;
  return result;
}

// =============================================================================
// Rule 6: prototype-pollution-lodash-merge-user-input
// =============================================================================

// ruleid: prototype-pollution-lodash-merge-user-input
app.post('/lodash-merge-vuln', (req, res) => {
  const defaults = { retries: 3 };
  _.merge(defaults, req.body);
  res.json(defaults);
});

// ruleid: prototype-pollution-lodash-merge-user-input
app.post('/lodash-defaults-deep-vuln', (req, res) => {
  const config = { database: { host: 'localhost' } };
  _.defaultsDeep(config, req.body);
  connect(config);
});

// ruleid: prototype-pollution-lodash-merge-user-input
app.post('/deepmerge-vuln', (req, res) => {
  const base = {};
  deepmerge(base, req.body);
});

// ok: prototype-pollution-lodash-merge-user-input
app.post('/lodash-merge-safe', (req, res) => {
  const sanitized = JSON.parse(JSON.stringify(req.body));
  const defaults = {};
  _.merge(defaults, sanitized);
});

// ok: prototype-pollution-lodash-merge-user-input
app.post('/lodash-merge-internal', (req, res) => {
  const internal = getInternalConfig();
  _.merge(defaults, internal);
});

// =============================================================================
// Complex attack scenarios from CVE-2025-55182
// =============================================================================

// ruleid: prototype-pollution-object-assign
// ruleid: prototype-pollution-to-child-process
app.post('/realistic-exploit-chain', (req, res) => {
  // Step 1: Pollution happens here
  const userConfig = Object.assign({}, req.body);

  // Step 2: Later in the code, any object inherits poisoned prototype
  const processOptions = {};

  // Step 3: RCE when options reach child_process
  exec('echo hello', processOptions);
});
